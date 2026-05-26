import json
import secrets
import re
import csv
import io
import os
import socket
import subprocess
import threading
import tempfile
import shutil
import time
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse
import ipaddress

from flask import (
    Blueprint, request, jsonify, render_template,
    make_response, Response, redirect, g, current_app
)

from app import db, bcrypt, csrf, mail
from app.models import (
    User, Camera, UserSession, Log, SignalingMessage, BlockedIP,
    WhitelistedIP, IncidentNote, AdminAction,
)
from app.security import (
    login_required, is_ip_blocked, is_rate_limited,
    create_session, revoke_session, block_ip, validate_session,
    normalize_ip, is_ip_whitelisted, get_security_settings, get_security_setting,
    set_security_setting, failed_login_count,
)
from app.logger import log_event, get_logs_for_user, subscribe, unsubscribe, push_to_user
from app.alerts import (
    alert_brute_force, alert_login, alert_ip_blocked,
    alert_new_user, alert_logout, alert_failed_login,
    alert_admin_access_denied, alert_idor_attempt, alert_rate_limit,
    alert_new_ip_login, alert_person_detected,
)

import queue as _queue

bp = Blueprint("main", __name__)

# ─────────────────────────────────────────────────────────────
# CSRF NOTE:
# We do NOT exempt the entire blueprint anymore.
# Public endpoints that need to be exempt are marked individually
# with @csrf.exempt below.
# ─────────────────────────────────────────────────────────────

MAX_FAILED = 5

_reset_tokens: dict = {}
RESET_TOKEN_EXPIRY_MINUTES = 30


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _get_csrf_token():
    """Read CSRF token from request header (sent by JS from the csrf_token cookie)."""
    return request.headers.get("X-CSRFToken", "")


def _audit_admin(action: str, target_type: str, target_id: str = "", details: dict = None):
    db.session.add(AdminAction(
        admin_id=getattr(g, "user", None).id if getattr(g, "user", None) else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details or {},
        ip_address=request.remote_addr,
    ))


def _duration_to_minutes(duration: str) -> int:
    mapping = {"1h": 60, "24h": 1440, "7d": 10080, "permanent": 0}
    return mapping.get(str(duration or "").lower(), 60)


def _public_user(u: User) -> dict:
    active_sessions = UserSession.query.filter_by(user_id=u.id, is_revoked=False).count()
    return {
        "id":              u.id,
        "username":        u.username,
        "email":           u.email,
        "role":            u.role,
        "is_active":       u.is_active,
        "must_reset_password": bool(u.must_reset_password),
        "admin_grace":      bool(getattr(u, "admin_grace", False)),
        "failed_attempts": u.failed_attempts,
        "active_sessions": active_sessions,
        "created_at":      u.created_at.isoformat(),
    }


def _is_safe_url(url: str) -> bool:
    """
    Block requests to private/internal IP ranges and known cloud metadata endpoints.
    This prevents attackers from using the camera proxy to probe Railway's internal network.
    """
    blocked_hostnames = {
        "169.254.169.254",         # AWS / GCP metadata
        "metadata.google.internal",
        "metadata.google",
        "localhost",
        "127.0.0.1",
        "::1",
    }
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if not hostname:
            return False

        if hostname.lower() in blocked_hostnames:
            return False

        # Allow http, https, and streaming protocols consumed by the FFmpeg proxy
        if parsed.scheme not in ("http", "https", "rtsp", "rtmp", "rtmps", "onvif"):
            return False

        # Try to parse as IP and block private/loopback/link-local ranges
        try:
            ip = ipaddress.ip_address(hostname)
            # EXEMPT all RFC-1918 private LAN ranges for local camera access
            # (192.168.x.x, 10.x.x.x, 172.16-31.x.x) — the user is connecting
            # to their own camera on their own network. Block everything else
            # that is private/loopback/link-local to prevent SSRF against cloud
            # metadata endpoints and internal services.
            if ip.is_private:
                # Allow home/office LAN cameras but still block loopback and
                # link-local (169.254.x.x is AWS metadata, ::1 is loopback).
                if ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return False
                # All RFC-1918 addresses (10/8, 172.16/12, 192.168/16) are OK
                return True

            if ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        except ValueError:
            pass

        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# CAMERA CREDENTIAL ENCRYPTION
#
# Camera passwords are encrypted at rest using Fernet (AES-128-CBC
# + HMAC-SHA256). The key is derived from the app SECRET_KEY so no
# extra environment variable is needed.
#
# Existing rows that contain plaintext passwords (before this change)
# are handled gracefully: decrypt() catches InvalidToken and falls back
# to returning the value as-is, so old credentials keep working until
# the user saves the camera settings again (which then stores them
# encrypted).
# ─────────────────────────────────────────────────────────────

def _fernet():
    import base64
    import hashlib
    from cryptography.fernet import Fernet
    raw = current_app.config["SECRET_KEY"]
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
    return Fernet(key)


def _encrypt_cam_password(plaintext: str) -> str:
    if not plaintext:
        return ""
    try:
        return _fernet().encrypt(plaintext.encode()).decode()
    except Exception:
        return plaintext


def _decrypt_cam_password(stored: str) -> str:
    if not stored:
        return ""
    try:
        from cryptography.fernet import InvalidToken
        return _fernet().decrypt(stored.encode()).decode()
    except Exception:
        # Graceful fallback for existing plaintext passwords already in the DB
        return stored


def admin_required(f):
    """
    Self-contained admin decorator — validates session and checks admin role.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        ip    = request.remote_addr
        token = request.cookies.get("cctv_session")
        if is_ip_blocked(ip):
            return jsonify({"error": "Your IP is blocked."}), 403

        sess = validate_session(token, ip) if token else None
        if not sess:
            return jsonify({"error": "Session expired."}), 401

        user = db.session.get(User, sess.user_id)
        if not user or not user.is_active:
            return jsonify({"error": "Account inactive."}), 401
        if user.role != "admin":
            return jsonify({"error": "Admin access required."}), 403
        g.user    = user
        g.session = sess
        return f(*args, **kwargs)
    return decorated


# ═══════════════════════════════════════════════════════
# PAGE ROUTES
# ═══════════════════════════════════════════════════════

@bp.route("/")
@login_required
def index():
    if g.user.role == "admin":
        return redirect("/dashboard")
    return redirect("/camera")

@bp.route("/dashboard")
@admin_required
def dashboard():
    all_users = User.query.all()
    return render_template("dashboard.html", user=g.user, all_users=all_users)

@bp.route("/camera")
@login_required
def camera_page():
    # Fetch ALL cameras for the user instead of just the first one
    cams = Camera.query.filter_by(user_id=g.user.id).all()
    stun = current_app.config["STUN_SERVERS"]
    # Pass 'cameras' list to the template
    return render_template("camera.html", user=g.user, cameras=cams,
                           stun_servers=json.dumps(stun))

@bp.route("/login")
def login_page():
    return render_template("login.html", reason=request.args.get("reason", ""))

@bp.route("/register")
def register_page():
    return render_template("register.html")

@bp.route("/settings")
@login_required
def settings_page():
    # Fetch ALL cameras for this user instead of just the first one
    cams = Camera.query.filter_by(user_id=g.user.id).all()
    return render_template("settings.html", user=g.user, cameras=cams)

@bp.route("/admin")
@admin_required
def admin_page():
    if g.user.role != "admin":
        log_event(
            "AUTH",
            f"Unauthorized admin access attempt by {g.user.username}",
            "CRITICAL",
            g.user.id,
            request.remote_addr
        )
        alert_admin_access_denied(
            g.user.discord_webhook or "",
            g.user.username,
            request.remote_addr,
        )
        return redirect("/")

    return render_template("admin.html", user=g.user)

@bp.route("/forgot-password")
def forgot_password_page():
    return render_template("forgot_password.html")

@bp.route("/healthz")
def healthz():
    return jsonify({"ok": True}), 200


# ═══════════════════════════════════════════════════════
# AUTH
# Public endpoints are individually CSRF-exempt because
# the user has no session cookie yet to read the CSRF token from.
# ═══════════════════════════════════════════════════════

@bp.route("/api/register", methods=["POST"])
@csrf.exempt
def api_register():
    ip   = request.remote_addr
    data = request.get_json(silent=True) or {}

    if is_ip_blocked(ip):
        return jsonify({"error": "Your IP is blocked."}), 403
    if is_rate_limited(ip, limit=5, window=60):
        return jsonify({"error": "Too many requests. Slow down."}), 429

    email    = data.get("email", "").strip().lower()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if not re.search(r"[A-Z]", password):
        return jsonify({"error": "Password must contain an uppercase letter."}), 400
    if not re.search(r"[0-9]", password):
        return jsonify({"error": "Password must contain a number."}), 400
    if not re.search(r"[^A-Za-z0-9]", password):
        return jsonify({"error": "Password must contain a special character."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered."}), 409

    is_first = User.query.count() == 0
    role     = "admin" if is_first else "user"

    user = User(
        email         = email,
        username      = username,
        password_hash = bcrypt.generate_password_hash(password).decode("utf-8"),
        role          = role,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(Camera(user_id=user.id, label="My Camera", stream_url=""))
    db.session.commit()

    log_event("AUTH", f"New user registered: {username} (role={role})", "INFO", user.id, ip)
    alert_new_user("", username, ip)
    return jsonify({"ok": True, "role": role}), 201


@bp.route("/api/login", methods=["POST"])
@csrf.exempt
def api_login():
    ip   = request.remote_addr
    data = request.get_json(silent=True) or {}
    settings = get_security_settings()

    identifier_raw   = data.get("identifier", data.get("email", "")).strip()
    identifier_lower = identifier_raw.lower()
    password         = data.get("password", "")

    # ── PRE-CHECK: look up user BEFORE rate-limit checks so admins are never blocked ──
    # Admin Grace Mode: if the login attempt is for an admin account, we skip
    # IP blocking and rate limiting entirely. This ensures the admin (janmarcluzong200@gmail.com)
    # is NEVER locked out — even during brute-force scenarios or presentation rushes.
    user = User.query.filter(
        (User.email == identifier_lower) | (User.username == identifier_raw)
    ).filter_by(is_active=True).first()

    is_admin_account = bool(user and (user.admin_grace or user.role == "admin"))

    # Only apply IP block and rate limit checks to non-admin accounts
    if not is_admin_account:
        if is_ip_blocked(ip):
            return jsonify({"error": "Your IP is temporarily blocked."}), 403
        if is_rate_limited(ip, limit=10, window=60):
            block_ip(ip, 5, "Rate limit exceeded on login")
            alert_ip_blocked("", ip, "Rate limit exceeded on login")
            return jsonify({"error": "Too many attempts. Blocked for 5 minutes."}), 429
    # ── END ADMIN GRACE PRE-CHECK ─────────────────────────────────────────────────────

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        if user:
            user.failed_attempts += 1
            db.session.commit()
            # ── ADMIN GRACE MODE: never auto-block the admin account's IP ──
            # This prevents the admin from being locked out during presentations
            # or when mistyping their password. Normal users still get blocked.
            # ─────────────────────────────────────────────────────────────
            if not is_admin_account and user.failed_attempts >= int(settings["failed_login_threshold"]):
                minutes = int(settings["auto_block_minutes"])
                if settings["auto_block_enabled"] and block_ip(ip, minutes, "Brute force detected"):
                    alert_brute_force(user.discord_webhook or "", ip, user.failed_attempts)
                    return jsonify({"error": "Too many failures. IP blocked temporarily."}), 403

        log_event("AUTH", f"Failed login attempt for: {identifier_raw}", "WARNING", None, ip)
        # Also skip IP-level threshold block if admin grace is active
        if not is_admin_account:
            if settings["auto_block_enabled"] and failed_login_count(ip, int(settings["failed_login_window"])) >= int(settings["failed_login_threshold"]):
                if block_ip(ip, int(settings["auto_block_minutes"]), "Failed-login threshold exceeded"):
                    alert_brute_force(user.discord_webhook if user else "", ip,
                                      user.failed_attempts if user else int(settings["failed_login_threshold"]))
                    return jsonify({"error": "Too many failures. IP blocked temporarily."}), 403
        alert_failed_login("", identifier_raw, ip)
        return jsonify({"error": "Invalid credentials."}), 401

    user.failed_attempts = 0
    db.session.commit()

    token = create_session(str(user.id), ip, request.headers.get("User-Agent", ""))
    log_event("AUTH", f"Login from {ip}", "INFO", user.id, ip)
    alert_login(user.discord_webhook or "", user.username, ip)

    # ── NEW IP DETECTION ──────────────────────────────────────────────────
    # Check if this IP has been seen before for this user in past sessions.
    # >1 because the new session was just created above by create_session().
    seen_before = UserSession.query.filter_by(
        user_id=user.id, ip_address=ip
    ).count() > 1
    if not seen_before:
        log_event("AUTH", f"Login from new/unseen IP: {ip}", "WARNING", user.id, ip)
        alert_new_ip_login(user.discord_webhook or "", user.username, ip)
    # ─────────────────────────────────────────────────────────────────────

    resp = make_response(jsonify({
        "ok": True,
        "role": user.role,
        "must_reset_password": bool(user.must_reset_password),
    }))
    resp.set_cookie(
        "cctv_session", token,
        httponly = True,
        samesite = "Lax",
        secure   = current_app.config["SESSION_COOKIE_SECURE"],
        max_age  = 60 * 60 * 8,
    )
    return resp


@bp.route("/api/logout", methods=["POST"])
@login_required
def api_logout():
    revoke_session(request.cookies.get("cctv_session", ""))
    log_event("SESSION", "User logged out", "INFO", g.user.id, request.remote_addr)
    alert_logout(g.user.discord_webhook or "", g.user.username, request.remote_addr)
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie("cctv_session")
    return resp


@bp.route("/logout", methods=["GET"])
@login_required
def page_logout():
    revoke_session(request.cookies.get("cctv_session", ""))
    log_event("SESSION", "User logged out", "INFO", g.user.id, request.remote_addr)
    alert_logout(g.user.discord_webhook or "", g.user.username, request.remote_addr)
    resp = make_response(redirect("/login"))
    resp.delete_cookie("cctv_session")
    return resp


# ═══════════════════════════════════════════════════════
# ACCOUNT & CAMERA
# ═══════════════════════════════════════════════════════

@bp.route("/api/account")
@login_required
def get_account():
    cam = Camera.query.filter_by(user_id=g.user.id).first()
    return jsonify({
        "username":        g.user.username,
        "email":           g.user.email,
        "role":            g.user.role,
        "discord_webhook": g.user.discord_webhook or "",
        "admin_webhook":   g.user.admin_webhook or "",
        "camera": {
            "id":         cam.id if cam else None,
            "stream_url": cam.stream_url if cam else "",
            "label":      cam.label if cam else "My Camera",
            "ai_enabled": cam.ai_enabled if cam else False,
        }
    })

@bp.route("/api/camera", methods=["POST"])
@login_required
def save_camera():
    data = request.get_json(silent=True) or {}
    cam_id = data.get("id")
    
    if cam_id:
        # Update existing camera
        cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()
        if not cam:
            return jsonify({"error": "Camera not found."}), 404
    else:
        # Create new camera
        cam = Camera(user_id=g.user.id)
        db.session.add(cam)
        
    cam.stream_url = data.get("stream_url", "").strip()
    cam.audio_url  = data.get("audio_url", "").strip()
    cam.label      = data.get("label", "New Camera").strip()[:128]
    cam.ai_enabled = bool(data.get("ai_enabled", False))
    cam.cam_username = data.get("cam_username", "").strip()
    raw_password = data.get("cam_password", "").strip()
    if raw_password:
        cam.cam_password = _encrypt_cam_password(raw_password)
    # If cam_password is empty/omitted, leave the existing stored value unchanged
    db.session.commit()
    
    log_event("CAMERA", f"Camera updated: {cam.label}", "INFO", g.user.id, request.remote_addr)
    return jsonify({"ok": True, "camera_id": cam.id})


@bp.route("/api/camera/ffmpeg-proxy")
@login_required
def ffmpeg_proxy():
    """
    Server-side FFmpeg subprocess proxy for LAN cameras.
    Pulls RTSP / RTMP / RTMPS / ONVIF / HTTP streams and re-encodes
    them as MJPEG multipart so the browser can display them directly.
    Works on local LAN because Flask and the camera share the same network.
    """
    from flask import stream_with_context

    cam_id = request.args.get("cam_id")
    cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()
    if not cam:
        return jsonify({"error": "camera_not_found"}), 404

    if not shutil.which("ffmpeg"):
        return jsonify({
            "error": "ffmpeg_not_found",
            "message": (
                "FFmpeg is not installed on the server. "
                "Linux: sudo apt install ffmpeg  |  "
                "Windows: winget install ffmpeg  |  "
                "Mac: brew install ffmpeg"
            )
        }), 503

    stream_url = (cam.stream_url or "").strip()
    if not stream_url:
        return jsonify({"error": "no_stream_url",
                        "message": "No stream URL configured for this camera."}), 400

    # SSRF guard — validate before embedding credentials or spawning FFmpeg
    if not _is_safe_url(stream_url):
        log_event("SECURITY", f"Blocked SSRF attempt via ffmpeg proxy: {stream_url}",
                  "CRITICAL", g.user.id, request.remote_addr)
        return jsonify({"error": "Invalid camera URL."}), 400

    # Embed stored credentials into the URL if not already present
    cam_user = getattr(cam, "cam_username", "") or ""
    cam_pass = _decrypt_cam_password(getattr(cam, "cam_password", "") or "")
    if cam_user and cam_pass:
        try:
            from urllib.parse import urlparse, urlunparse
            p = urlparse(stream_url)
            if not p.username:
                netloc = f"{cam_user}:{cam_pass}@{p.hostname}"
                if p.port:
                    netloc += f":{p.port}"
                stream_url = urlunparse(p._replace(netloc=netloc))
        except Exception:
            pass

    scheme = stream_url.split("://")[0].lower() if "://" in stream_url else "http"

    # Protocol-specific FFmpeg input flags
    rtsp_flags = ["-rtsp_transport", "tcp"] if scheme == "rtsp" else []

    cmd = [
        "ffmpeg",
        "-loglevel", "warning",
        "-fflags", "nobuffer+discardcorrupt",
        "-flags", "low_delay",
        *rtsp_flags,
        "-i", stream_url,
        "-an",              # video-only MJPEG stream — audio is served separately via /api/camera/ffmpeg-audio
        "-vf", "fps=15",
        "-f", "image2pipe",
        "-vcodec", "mjpeg",
        "-q:v", "5",
        "-vsync", "drop",
        "-"
    ]

    def generate():
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        buf = b""
        try:
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                buf += chunk
                # Extract complete JPEG frames by SOI (\xff\xd8) / EOI (\xff\xd9) markers
                while True:
                    s = buf.find(b"\xff\xd8")
                    if s == -1:
                        # Trim oversized buffer but keep tail for split-marker safety
                        buf = buf[-2048:] if len(buf) > 131072 else buf
                        break
                    e = buf.find(b"\xff\xd9", s + 2)
                    if e == -1:
                        break
                    frame = buf[s:e + 2]
                    buf = buf[e + 2:]
                    yield (
                        b"--frame\r\n"
                        b"Content-Type: image/jpeg\r\n\r\n"
                        + frame
                        + b"\r\n"
                    )
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                pass

    return Response(
        stream_with_context(generate()),
        content_type="multipart/x-mixed-replace; boundary=frame",
        headers={
            "Cache-Control": "no-cache, no-store",
            "X-Accel-Buffering": "no",
        },
    )

@bp.route("/api/camera/ffmpeg-audio")
@login_required
def ffmpeg_audio_proxy():
    """
    Server-side FFmpeg audio-only proxy for RTSP / RTMP / RTMPS / ONVIF streams.
    Extracts audio from the stream and re-encodes it as Ogg/Opus so the browser
    can play it via the mic button — no client-side FFmpeg needed.
    """
    from flask import stream_with_context

    cam_id = request.args.get("cam_id")
    cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()
    if not cam:
        return jsonify({"error": "camera_not_found"}), 404

    if not shutil.which("ffmpeg"):
        return jsonify({
            "error": "ffmpeg_not_found",
            "message": "FFmpeg is not installed on the server.",
        }), 503

    stream_url = (cam.stream_url or "").strip()
    if not stream_url:
        return jsonify({"error": "no_stream_url",
                        "message": "No stream URL configured for this camera."}), 400

    # SSRF guard — validate before embedding credentials or spawning FFmpeg
    if not _is_safe_url(stream_url):
        log_event("SECURITY", f"Blocked SSRF attempt via ffmpeg audio proxy: {stream_url}",
                  "CRITICAL", g.user.id, request.remote_addr)
        return jsonify({"error": "Invalid camera URL."}), 400

    # Embed credentials if stored
    cam_user = getattr(cam, "cam_username", "") or ""
    cam_pass = _decrypt_cam_password(getattr(cam, "cam_password", "") or "")
    if cam_user and cam_pass:
        try:
            from urllib.parse import urlparse, urlunparse
            p = urlparse(stream_url)
            if not p.username:
                netloc = f"{cam_user}:{cam_pass}@{p.hostname}"
                if p.port:
                    netloc += f":{p.port}"
                stream_url = urlunparse(p._replace(netloc=netloc))
        except Exception:
            pass

    scheme = stream_url.split("://")[0].lower() if "://" in stream_url else "http"
    rtsp_flags = ["-rtsp_transport", "tcp"] if scheme == "rtsp" else []

    cmd = [
        "ffmpeg",
        "-loglevel", "warning",
        "-fflags", "nobuffer+discardcorrupt",
        "-flags", "low_delay",
        *rtsp_flags,
        "-i", stream_url,
        "-vn",              # audio-only — drop video
        "-c:a", "aac",      # AAC: compiled into every standard FFmpeg build
        "-b:a", "32k",
        "-f", "adts",       # ADTS container — raw AAC frames, no header needed by browser
        "-"
    ]

    def generate():
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                yield chunk
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                pass

    return Response(
        stream_with_context(generate()),
        content_type="audio/aac",
        headers={
            "Cache-Control": "no-cache, no-store",
            "X-Accel-Buffering": "no",
        },
    )


@bp.route("/api/camera/delete", methods=["POST"])
@login_required
def delete_camera():
    data = request.get_json(silent=True) or {}
    cam_id = data.get("id")
    
    if not cam_id:
        return jsonify({"error": "Camera ID required"}), 400
        
    cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()
    if not cam:
        return jsonify({"error": "Camera not found or unauthorized"}), 404
        
    db.session.delete(cam)
    db.session.commit()
    
    from app.logger import log_event
    log_event("CAMERA", f"Camera deleted: {cam.label}", "INFO", g.user.id, request.remote_addr)
    
    return jsonify({"ok": True})

@bp.route("/api/account/nickname", methods=["POST"])
@login_required
def change_nickname():
    data = request.get_json(silent=True) or {}
    new_nickname = data.get("nickname", "").strip()

    if len(new_nickname) < 3 or len(new_nickname) > 16:
        return jsonify({"error": "Nickname must be between 3 and 16 characters long."}), 400
    if not re.match(r"^[a-zA-Z0-9_.#]+$", new_nickname):
        return jsonify({"error": "Nickname can only contain letters, numbers, and the symbols _ . #"}), 400

    existing = User.query.filter_by(username=new_nickname).first()
    if existing and existing.id != g.user.id:
        return jsonify({"error": "This nickname is already taken by another user."}), 409

    old_nickname = g.user.username
    g.user.username = new_nickname
    db.session.commit()

    log_event(
        "ACCOUNTS",
        f"Display alias modification applied. Changed from '{old_nickname}' to '{new_nickname}'.",
        "INFO",
        g.user.id,
        request.remote_addr
    )

    return jsonify({"ok": True})

@bp.route("/api/account/password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    old  = data.get("old_password", "")
    new  = data.get("new_password", "")
    if not bcrypt.check_password_hash(g.user.password_hash, old):
        return jsonify({"error": "Current password is incorrect."}), 403
    if len(new) < 8:
        return jsonify({"error": "New password must be at least 8 characters."}), 400
    if not re.search(r"[A-Z]", new):
        return jsonify({"error": "New password must contain an uppercase letter."}), 400
    if not re.search(r"[0-9]", new):
        return jsonify({"error": "New password must contain a number."}), 400
    if not re.search(r"[^A-Za-z0-9]", new):
        return jsonify({"error": "New password must contain a special character."}), 400
    g.user.password_hash = bcrypt.generate_password_hash(new).decode("utf-8")
    g.user.must_reset_password = False
    UserSession.query.filter(
        UserSession.user_id == g.user.id,
        UserSession.id != g.session.id,
    ).update({"is_revoked": True}, synchronize_session=False)
    db.session.commit()
    log_event("AUTH", "Password changed", "INFO", g.user.id, request.remote_addr)
    return jsonify({"ok": True})


@bp.route("/api/account/delete", methods=["POST"])
@login_required
def delete_account():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Password is required to delete your account."}), 400
    if not bcrypt.check_password_hash(g.user.password_hash, password):
        return jsonify({"error": "Incorrect password."}), 403
    if g.user.role == "admin":
        admin_count = User.query.filter_by(role="admin").count()
        if admin_count <= 1:
            return jsonify({"error": "Cannot delete the last admin account."}), 403

    from app.models import PasswordResetToken
    user_id = g.user.id
    log_event("ACCOUNTS", f"Account deleted: '{g.user.username}'.", "WARNING", user_id, request.remote_addr)

    # PasswordResetToken has no ORM cascade — delete manually first
    PasswordResetToken.query.filter_by(user_id=str(user_id)).delete()
    db.session.flush()
    # Camera, Log, UserSession, Detection all have cascade="all, delete-orphan"
    # and are removed automatically when the User row is deleted
    db.session.delete(g.user)
    db.session.commit()

    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie("cctv_session")
    return resp


@bp.route("/api/account/webhook", methods=["POST"])
@login_required
def save_webhook():
    data = request.get_json(silent=True) or {}
    url  = data.get("webhook_url", "").strip()
    if url and not (
        url.startswith("https://discord.com/api/webhooks/") or
        url.startswith("https://discordapp.com/api/webhooks/")
    ):
        return jsonify({"error": "Invalid Discord webhook URL."}), 400
    g.user.discord_webhook = url or None
    db.session.commit()
    log_event("SYSTEM", "Personal webhook updated", "INFO", g.user.id, request.remote_addr)
    return jsonify({"ok": True})

# ═══════════════════════════════════════════════════════
# STATUS
# ═══════════════════════════════════════════════════════

@bp.route("/api/status")
@login_required
def status():
    cam = Camera.query.filter_by(user_id=g.user.id).first()
    return jsonify({
        "username":   g.user.username,
        "role":       g.user.role,
        "camera_url": cam.stream_url if cam else "",
        "ai_enabled": cam.ai_enabled if cam else False,
        "session_ok": True,
    })


# ═══════════════════════════════════════════════════════
# SIGNALING
# ═══════════════════════════════════════════════════════

@bp.route("/api/signal/send", methods=["POST"])
@login_required
def signal_send():
    data     = request.get_json(silent=True) or {}
    room_id  = data.get("room_id", "")
    sender   = data.get("sender", "")
    msg_type = data.get("type", "")
    payload  = data.get("payload", "")

    if str(room_id) != str(g.user.id):
        log_event(
            "SIGNALING",
            f"IDOR attempt on room {room_id}",
            "CRITICAL",
            g.user.id,
            request.remote_addr
        )
        alert_idor_attempt(
            g.user.discord_webhook or "",
            g.user.username,
            request.remote_addr,
            room_id,
        )
        return jsonify({"error": "Access denied."}), 403

    if sender not in ("camera", "viewer") or msg_type not in ("offer", "answer", "ice"):
        return jsonify({"error": "Invalid signal parameters."}), 400

    cutoff = datetime.utcnow() - timedelta(seconds=60)
    SignalingMessage.query.filter(
        SignalingMessage.room_id == room_id,
        SignalingMessage.created_at < cutoff
    ).delete()

    db.session.add(SignalingMessage(
        room_id=room_id, sender=sender,
        msg_type=msg_type, payload=json.dumps(payload)
    ))
    db.session.commit()
    return jsonify({"ok": True})


@bp.route("/api/signal/poll")
@login_required
def signal_poll():
    room_id = request.args.get("room_id", "")
    caller  = request.args.get("caller", "")
    if str(room_id) != str(g.user.id):
        return jsonify({"error": "Access denied."}), 403
    other = "viewer" if caller == "camera" else "camera"
    msgs  = SignalingMessage.query.filter_by(
        room_id=room_id, sender=other, consumed=False
    ).order_by(SignalingMessage.id.asc()).all()
    results = []
    for m in msgs:
        results.append({"type": m.msg_type, "payload": json.loads(m.payload)})
        m.consumed = True
    db.session.commit()
    return jsonify({"messages": results})


# ═══════════════════════════════════════════════════════
# LOGS
# ═══════════════════════════════════════════════════════

@bp.route("/api/logs")
@login_required
def get_logs():
    return jsonify(get_logs_for_user(g.user.id, 100, request.args.get("severity")))


@bp.route("/api/logs/stream")
@login_required
def log_stream():
    uid          = g.user.id
    history      = list(reversed(get_logs_for_user(uid, 20)))
    history_json = [json.dumps(e) for e in history]

    def gen():
        for entry_json in history_json:
            yield f"data: {entry_json}\n\n"
        q = subscribe(uid)
        try:
            while True:
                try:
                    data = q.get(timeout=20)
                    yield f"data: {json.dumps(data)}\n\n"
                except _queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            unsubscribe(uid, q)

    return Response(
        gen(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        }
    )


@bp.route("/api/logs/clear", methods=["POST"])
@login_required
def clear_logs():
    Log.query.filter_by(user_id=g.user.id).delete()
    db.session.commit()
    push_to_user(g.user.id, {"__action": "clear"})
    log_event("SYSTEM", "Logs cleared by user", "INFO", g.user.id, request.remote_addr)
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════
# ADMIN
# ═══════════════════════════════════════════════════════

@bp.route("/api/admin/webhook", methods=["GET"])
@admin_required
def get_admin_webhook():
    return jsonify({"admin_webhook": g.user.admin_webhook or ""})


@bp.route("/api/admin/webhook/debug")
@admin_required
def debug_admin_webhook():
    """Debug endpoint — confirms what webhook URL is currently stored."""
    from app.alerts import _fetch_admin_webhook_from_db
    live = _fetch_admin_webhook_from_db()
    return jsonify({
        "db_row_admin_webhook":   g.user.admin_webhook or "",
        "live_result_from_orm":   live,
        "match":                  (g.user.admin_webhook or "") == live,
    })


@bp.route("/api/admin/webhook", methods=["POST"])
@admin_required
def save_admin_webhook():
    data = request.get_json(silent=True) or {}
    url  = data.get("admin_webhook", "").strip()
    if url and not (
        url.startswith("https://discord.com/api/webhooks/") or
        url.startswith("https://discordapp.com/api/webhooks/")
    ):
        return jsonify({"error": "Invalid Discord webhook URL."}), 400
    g.user.admin_webhook = url or None
    db.session.commit()
    from app.alerts import invalidate_admin_webhook_cache
    invalidate_admin_webhook_cache()
    log_event("SYSTEM", "Admin global webhook updated", "INFO",
              g.user.id, request.remote_addr)
    return jsonify({"ok": True})


# NOTE: /api/admin/make-me-admin has been REMOVED.
# Use the ADMIN_EMAIL environment variable in Railway to promote the first admin.
# This endpoint was a security risk — any logged-in user could call it
# if the check had any edge case.


@bp.route("/api/admin/stats")
@admin_required
def admin_stats():
    cutoff     = datetime.utcnow() - timedelta(hours=24)
    failed_24h = Log.query.filter(
        Log.severity   == "WARNING",
        Log.event_type == "AUTH",
        Log.timestamp  >= cutoff
    ).count()
    suspicious_ips = db.session.query(Log.ip_address).filter(
        Log.ip_address.isnot(None),
        Log.severity.in_(("WARNING", "ALERT", "CRITICAL")),
        Log.timestamp >= cutoff,
    ).distinct().count()
    return jsonify({
        "total_users":       User.query.count(),
        "failed_logins_24h": failed_24h,
        "blocked_ips":       BlockedIP.query.filter(BlockedIP.blocked_until >= datetime.utcnow()).count(),
        "total_logs":        Log.query.count(),
        "active_threats":    suspicious_ips,
    })


@bp.route("/api/admin/logs")
@admin_required
def admin_logs():
    logs     = Log.query.order_by(Log.timestamp.desc()).limit(500).all()
    user_map = {u.id: u.username for u in User.query.all()}
    return jsonify([{
        "id":          l.id,
        "severity":    l.severity,
        "event_type":  l.event_type,
        "description": l.description,
        "ip":          l.ip_address or "",
        "user_id":     l.user_id or "",
        "username":    user_map.get(l.user_id, "") if l.user_id else "system",
        "timestamp":   l.timestamp.isoformat(),
    } for l in logs])


@bp.route("/api/admin/blocked")
@admin_required
def admin_blocked():
    blocked = BlockedIP.query.order_by(BlockedIP.created_at.desc()).all()
    return jsonify([{
        "id":            b.id,
        "ip_address":    b.ip_address,
        "reason":        b.reason or "",
        "blocked_until": b.blocked_until.isoformat(),
        "created_at":    b.created_at.isoformat(),
    } for b in blocked])


@bp.route("/api/admin/whitelist")
@admin_required
def admin_whitelist():
    rows = WhitelistedIP.query.order_by(WhitelistedIP.created_at.desc()).all()
    return jsonify([{
        "id": w.id,
        "ip_address": w.ip_address,
        "reason": w.reason or "",
        "created_at": w.created_at.isoformat(),
    } for w in rows])


@bp.route("/api/admin/users")
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify([_public_user(u) for u in users])


@bp.route("/api/admin/users/role", methods=["POST"])
@admin_required
def admin_set_user_role():
    data     = request.get_json(silent=True) or {}
    user_id  = data.get("user_id", "").strip()
    new_role = data.get("role", "").strip().lower()

    if new_role not in ("admin", "user"):
        return jsonify({"error": "Invalid role. Must be 'admin' or 'user'."}), 400

    if not user_id:
        return jsonify({"error": "user_id is required."}), 400

    if str(user_id) == str(g.user.id):
        return jsonify({"error": "You cannot change your own role."}), 403

    target = db.session.get(User, user_id)
    if not target:
        return jsonify({"error": "User not found."}), 404

    old_role    = target.role
    target.role = new_role
    db.session.commit()

    log_event(
        "AUTH",
        f"Admin {g.user.username} changed role of {target.username}: {old_role} to {new_role}",
        "INFO",
        g.user.id,
        request.remote_addr,
    )
    return jsonify({"ok": True, "username": target.username, "role": new_role})


@bp.route("/api/admin/unblock", methods=["POST"])
@admin_required
def admin_unblock():
    ip  = normalize_ip((request.get_json(silent=True) or {}).get("ip", ""))
    if not ip:
        return jsonify({"error": "Invalid IP address."}), 400
    rec = BlockedIP.query.filter_by(ip_address=ip).first()
    if rec:
        db.session.delete(rec)
        _audit_admin("unblock_ip", "ip", ip)
        db.session.commit()
        log_event("NETWORK", f"Admin unblocked IP: {ip}", "INFO",
                  g.user.id, request.remote_addr)
    return jsonify({"ok": True})


@bp.route("/api/admin/block", methods=["POST"])
@admin_required
def admin_block():
    data = request.get_json(silent=True) or {}
    ip = normalize_ip(data.get("ip", ""))
    if not ip:
        return jsonify({"error": "Invalid IP address."}), 400
    if is_ip_whitelisted(ip):
        return jsonify({"error": "IP is whitelisted. Remove whitelist before blocking."}), 409
    minutes = _duration_to_minutes(data.get("duration", "1h"))
    reason = (data.get("reason") or "Manual admin block")[:256]
    if block_ip(ip, minutes, reason, created_by=g.user.id):
        _audit_admin("block_ip", "ip", ip, {"duration": data.get("duration", "1h"), "reason": reason})
        db.session.commit()
    return jsonify({"ok": True})


@bp.route("/api/admin/whitelist", methods=["POST"])
@admin_required
def admin_add_whitelist():
    data = request.get_json(silent=True) or {}
    ip = normalize_ip(data.get("ip", ""))
    if not ip:
        return jsonify({"error": "Invalid IP address."}), 400
    rec = WhitelistedIP.query.filter_by(ip_address=ip).first()
    if not rec:
        db.session.add(WhitelistedIP(
            ip_address=ip,
            reason=(data.get("reason") or "Trusted IP")[:256],
            created_by=g.user.id,
        ))
    BlockedIP.query.filter_by(ip_address=ip).delete()
    _audit_admin("whitelist_ip", "ip", ip)
    db.session.commit()
    log_event("NETWORK", f"Admin whitelisted IP: {ip}", "INFO", g.user.id, request.remote_addr)
    return jsonify({"ok": True})


@bp.route("/api/admin/whitelist/remove", methods=["POST"])
@admin_required
def admin_remove_whitelist():
    ip = normalize_ip((request.get_json(silent=True) or {}).get("ip", ""))
    if not ip:
        return jsonify({"error": "Invalid IP address."}), 400
    WhitelistedIP.query.filter_by(ip_address=ip).delete()
    _audit_admin("remove_whitelist", "ip", ip)
    db.session.commit()
    log_event("NETWORK", f"Admin removed whitelist IP: {ip}", "INFO", g.user.id, request.remote_addr)
    return jsonify({"ok": True})


@bp.route("/api/admin/users/action", methods=["POST"])
@admin_required
def admin_user_action():
    data = request.get_json(silent=True) or {}
    target = db.session.get(User, data.get("user_id", ""))
    action = data.get("action", "")
    if not target:
        return jsonify({"error": "User not found."}), 404
    if target.id == g.user.id and action in ("lock", "kill_sessions"):
        return jsonify({"error": "You cannot apply this action to your current admin account."}), 403
    if action == "kill_sessions":
        UserSession.query.filter_by(user_id=target.id, is_revoked=False).update({"is_revoked": True}, synchronize_session=False)
    elif action == "lock":
        target.is_active = False
        UserSession.query.filter_by(user_id=target.id, is_revoked=False).update({"is_revoked": True}, synchronize_session=False)
    elif action == "unlock":
        target.is_active = True
        target.failed_attempts = 0
    elif action == "force_password_reset":
        target.must_reset_password = True
        UserSession.query.filter_by(user_id=target.id, is_revoked=False).update({"is_revoked": True}, synchronize_session=False)
    else:
        return jsonify({"error": "Invalid action."}), 400
    _audit_admin(action, "user", target.id, {"username": target.username})
    db.session.commit()
    log_event("AUTH", f"Admin {g.user.username} applied {action} to {target.username}", "WARNING", g.user.id, request.remote_addr)
    return jsonify({"ok": True, "user": _public_user(target)})


@bp.route("/api/admin/security/settings", methods=["GET", "POST"])
@admin_required
def admin_security_settings():
    if request.method == "GET":
        return jsonify(get_security_settings())
    data = request.get_json(silent=True) or {}
    allowed_ints = {
        "failed_login_threshold": (2, 50),
        "failed_login_window": (10, 3600),
        "auto_block_minutes": (0, 43200),
        "live_refresh_seconds": (0, 300),
    }
    allowed_bools = {"auto_block_enabled", "maintenance_mode", "lockdown_mode", "honeypot_auto_block"}
    for key, value in data.items():
        if key in allowed_ints:
            low, high = allowed_ints[key]
            set_security_setting(key, min(max(int(value), low), high))
        elif key in allowed_bools:
            set_security_setting(key, bool(value))
    _audit_admin("security_settings_update", "settings", "security", data)
    db.session.commit()
    log_event("SYSTEM", "Admin updated security settings", "INFO", g.user.id, request.remote_addr)
    return jsonify({"ok": True, "settings": get_security_settings()})


@bp.route("/api/admin/users/grace", methods=["POST"])
@admin_required
def admin_toggle_grace():
    """Toggle Admin Grace (skip IP block & rate-limit) for a specific admin user."""
    data   = request.get_json(silent=True) or {}
    target = db.session.get(User, data.get("user_id", ""))
    if not target:
        return jsonify({"error": "User not found."}), 404
    if target.role != "admin":
        return jsonify({"error": "Admin Grace can only be granted to admin-role accounts."}), 400
    enabled = bool(data.get("enabled", False))
    target.admin_grace = enabled
    db.session.commit()
    _audit_admin("admin_grace_toggle", "user", target.id, {"enabled": enabled, "username": target.username})
    log_event("SYSTEM", f"Admin grace {'enabled' if enabled else 'disabled'} for {target.username} by {g.user.username}", "INFO", g.user.id, request.remote_addr)
    return jsonify({"ok": True, "user_id": target.id, "admin_grace": target.admin_grace})


@bp.route("/api/admin/threats")
@admin_required
def admin_threats():
    cutoff = datetime.utcnow() - timedelta(hours=24)
    rows = db.session.query(
        Log.ip_address,
        db.func.count(Log.id).label("events"),
        db.func.max(Log.timestamp).label("last_seen"),
    ).filter(
        Log.ip_address.isnot(None),
        Log.severity.in_(("WARNING", "ALERT", "CRITICAL")),
        Log.timestamp >= cutoff,
    ).group_by(Log.ip_address).order_by(db.func.count(Log.id).desc()).limit(10).all()
    return jsonify([{
        "ip": r.ip_address,
        "events": int(r.events),
        "last_seen": r.last_seen.isoformat(),
        "blocked": is_ip_blocked(r.ip_address),
        "whitelisted": is_ip_whitelisted(r.ip_address),
    } for r in rows])


@bp.route("/api/admin/timeline/<path:ip>")
@admin_required
def admin_timeline(ip):
    ip = normalize_ip(ip)
    if not ip:
        return jsonify({"error": "Invalid IP address."}), 400
    logs = Log.query.filter_by(ip_address=ip).order_by(Log.timestamp.asc()).limit(500).all()
    notes = IncidentNote.query.filter_by(ip_address=ip).order_by(IncidentNote.created_at.asc()).all()
    return jsonify({
        "ip": ip,
        "logs": [{
            "id": l.id,
            "severity": l.severity,
            "event_type": l.event_type,
            "description": l.description,
            "timestamp": l.timestamp.isoformat(),
        } for l in logs],
        "notes": [{
            "id": n.id,
            "admin_id": n.admin_id,
            "note": n.note,
            "created_at": n.created_at.isoformat(),
        } for n in notes],
    })


@bp.route("/api/admin/incident-note", methods=["POST"])
@admin_required
def admin_incident_note():
    data = request.get_json(silent=True) or {}
    ip = normalize_ip(data.get("ip", ""))
    note = (data.get("note") or "").strip()
    if not ip or not note:
        return jsonify({"error": "IP and note are required."}), 400
    db.session.add(IncidentNote(ip_address=ip, admin_id=g.user.id, note=note[:2000]))
    _audit_admin("incident_note", "ip", ip)
    db.session.commit()
    return jsonify({"ok": True})


@bp.route("/api/admin/export/<path:ip>")
@admin_required
def admin_export_ip(ip):
    ip = normalize_ip(ip)
    if not ip:
        return jsonify({"error": "Invalid IP address."}), 400
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "severity", "event_type", "description"])
    for l in Log.query.filter_by(ip_address=ip).order_by(Log.timestamp.asc()).all():
        writer.writerow([l.timestamp.isoformat(), l.severity, l.event_type, l.description])
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = f"attachment; filename=incident-{ip}.csv"
    return resp


@bp.route("/api/admin/ip-reputation/<path:ip>")
@admin_required
def admin_ip_reputation(ip):
    ip = normalize_ip(ip)
    if not ip:
        return jsonify({"error": "Invalid IP address."}), 400
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return jsonify({"configured": False, "message": "ABUSEIPDB_API_KEY is not configured."})
    try:
        r = _req.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8,
        )
        return jsonify({"configured": True, "result": r.json()}), r.status_code
    except Exception:
        return jsonify({"configured": True, "error": "Lookup failed."}), 502


@bp.route("/api/admin/reverse-dns/<path:ip>")
@admin_required
def admin_reverse_dns(ip):
    ip = normalize_ip(ip)
    if not ip:
        return jsonify({"error": "Invalid IP address."}), 400
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = ""
    return jsonify({"ip": ip, "hostname": hostname})


@bp.route("/api/admin/logs/clear-all", methods=["POST"])
@admin_required
def admin_clear_all_logs():
    Log.query.delete()
    db.session.commit()
    log_event("SYSTEM", "Admin cleared ALL logs", "INFO", g.user.id, request.remote_addr)
    return jsonify({"ok": True})

# ═══════════════════════════════════════════════════════
# FORGOT / RESET PASSWORD
# These are public so CSRF-exempt (user has no session yet).
# ═══════════════════════════════════════════════════════

@bp.route("/api/forgot-password", methods=["POST"])
@csrf.exempt
def api_forgot_password():
    import hashlib
    from app.models import PasswordResetToken

    data  = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()

    if not email or "@" not in email:
        return jsonify({"ok": True}), 200

    user = User.query.filter_by(email=email, is_active=True).first()
    if user:
        raw_token  = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expiry     = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES)

        PasswordResetToken.query.filter_by(user_id=str(user.id)).delete()
        db.session.add(PasswordResetToken(
            user_id    = str(user.id),
            token_hash = token_hash,
            expires_at = expiry,
        ))
        db.session.commit()

        reset_url = f"{request.host_url.rstrip('/')}/forgot-password?token={raw_token}"
        username  = user.username
        uid       = str(user.id)
        ip        = request.remote_addr

        try:
            import requests as _requests
            import os
            response = _requests.post(
                "https://api.brevo.com/v3/smtp/email",
                headers={
                    "accept": "application/json",
                    "api-key": os.environ.get("BREVO_API_KEY", ""),
                    "content-type": "application/json",
                },
                json={
                    "sender": {"name": "CatchCatchTV", "email": "janmarcluzong200@gmail.com"},
                    "to": [{"email": email}],
                    "subject": "CatchCatchTV — Password Reset",
                    "textContent": (
                        f"Hello {username}!\n\n"
                        f"Click the link below to reset your password "
                        f"(valid for {RESET_TOKEN_EXPIRY_MINUTES} minutes):\n"
                        f"{reset_url}\n\n"
                        f"— CatchCatchTV"
                    )
                },
                timeout=10
            )
            if response.status_code == 201:
                print(f"[RESET] Email sent successfully to {email}")
            else:
                print(f"[RESET] Brevo error: {response.status_code} {response.text}")
        except Exception as exc:
            print(f"[RESET] FAILED: {exc}")

        log_event("AUTH", f"Password reset requested for {email}", "INFO", uid, ip)

    return jsonify({"ok": True}), 200


@bp.route("/api/reset-password", methods=["POST"])
@csrf.exempt
def api_reset_password():
    import hashlib
    from app.models import PasswordResetToken

    data      = request.get_json(silent=True) or {}
    raw_token = data.get("token", "").strip()
    password  = data.get("password", "")

    if not raw_token:
        return jsonify({"error": "Invalid or missing reset token."}), 400

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    record     = PasswordResetToken.query.filter_by(
        token_hash=token_hash, used=False
    ).first()

    if not record:
        return jsonify({"error": "Invalid or expired reset link."}), 400
    if datetime.utcnow() > record.expires_at:
        db.session.delete(record)
        db.session.commit()
        return jsonify({"error": "Reset link has expired. Please request a new one."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if not re.search(r"[A-Z]", password):
        return jsonify({"error": "Password must contain an uppercase letter."}), 400
    if not re.search(r"[0-9]", password):
        return jsonify({"error": "Password must contain a number."}), 400
    if not re.search(r"[^A-Za-z0-9]", password):
        return jsonify({"error": "Password must contain a special character."}), 400

    user = db.session.get(User, record.user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    user.password_hash   = bcrypt.generate_password_hash(password).decode("utf-8")
    user.failed_attempts = 0
    record.used          = True
    db.session.commit()

    log_event("AUTH", "Password reset completed", "INFO",
              str(user.id), request.remote_addr)
    return jsonify({"ok": True}), 200


# ═══════════════════════════════════════════════════════
# AI DETECTIONS
# ═══════════════════════════════════════════════════════

@bp.route("/api/detections", methods=["POST"])
@login_required
def api_detections():
    from app.models import Detection

    data       = request.get_json(silent=True) or {}
    detections = data.get("detections", [])
    ip         = request.remote_addr
    camera_label = str(data.get("camera_label", "")).strip()[:64] or None
    cam_prefix = f"[{camera_label}] " if camera_label else ""

    if not detections or not isinstance(detections, list):
        return jsonify({"ok": True, "alert_triggered": False}), 200

    alert_triggered = False
    pending_logs = []

    for det in detections:
        detected_class = str(det.get("detected_class", ""))[:128]
        confidence     = float(det.get("confidence", 0.0))
        bounding_box   = det.get("bounding_box", {})
        is_alert       = bool(det.get("is_alert", False))

        entry = Detection(
            user_id        = g.user.id,
            detected_class = detected_class,
            confidence     = confidence,
            bounding_box   = bounding_box,
            is_alert       = is_alert,
            alert_sent     = False,
        )
        db.session.add(entry)

        if is_alert:
            pending_logs.append((
                "DETECTION",
                f"{cam_prefix}Person detected: {detected_class} ({confidence:.0%})",
                "ALERT",
            ))
        else:
            pending_logs.append((
                "DETECTION",
                f"{cam_prefix}Object detected: {detected_class} ({confidence:.0%})",
                "INFO",
            ))

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "DB error"}), 500

    for ev_type, ev_desc, ev_sev in pending_logs:
        log_event(ev_type, ev_desc, ev_sev, g.user.id, ip)

    if any(d.get("is_alert") for d in detections):
        from app.models import Detection as Det
        cutoff = datetime.utcnow() - timedelta(seconds=120)
        recent_alert = Det.query.filter(
            Det.user_id    == g.user.id,
            Det.is_alert   == True,
            Det.alert_sent == True,
            Det.timestamp  >= cutoff,
        ).first()

        if not recent_alert:
            person_dets = [d for d in detections if d.get("is_alert")]
            if person_dets:
                best = max(person_dets, key=lambda d: d.get("confidence", 0))
                alert_person_detected(
                    g.user.discord_webhook or "",
                    best.get("detected_class", "Person"),
                    best.get("confidence", 0.0),
                    datetime.utcnow(),
                )
                just_now = datetime.utcnow() - timedelta(seconds=5)
                latest = Det.query.filter(
                    Det.user_id    == g.user.id,
                    Det.is_alert   == True,
                    Det.alert_sent == False,
                    Det.timestamp  >= just_now,
                ).order_by(Det.timestamp.desc()).first()
                if latest:
                    latest.alert_sent = True
                    db.session.commit()
                alert_triggered = True

    return jsonify({"ok": True, "alert_triggered": alert_triggered}), 200



# ═══════════════════════════════════════════════════════
# CAMERA PROXY — SSRF protected, self-signed cert bypass,
# Digest auth support, redirect following, chunked streaming
# ═══════════════════════════════════════════════════════

import requests as _req
from requests.auth import HTTPDigestAuth as _DigestAuth

@bp.route("/api/camera/proxy")
@login_required
def camera_proxy():
    cam_id = request.args.get("cam_id")
    cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()

    if not cam or not cam.stream_url:
        return jsonify({"error": "No camera configured or found"}), 404

    if not _is_safe_url(cam.stream_url):
        log_event("SECURITY", f"Blocked SSRF attempt via camera proxy: {cam.stream_url}",
                  "CRITICAL", g.user.id, request.remote_addr)
        return jsonify({"error": "Invalid camera URL."}), 400

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cam_username = getattr(cam, "cam_username", None) or ""
    cam_password = _decrypt_cam_password(getattr(cam, "cam_password", None) or "")

    def _try_fetch(auth_obj):
        return _req.get(
            cam.stream_url,
            stream=True,
            timeout=(10, 0),       # 10 s to connect; no read timeout — stream runs indefinitely
            verify=False,          # bypass self-signed certs on IP cameras
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; CatchCatchTV-proxy/2.0)",
                "Accept": "*/*",
            },
            auth=auth_obj,
        )

    try:
        from flask import stream_with_context

        r = _try_fetch(None)

        # 401 → retry with Digest auth (most IP cameras), then fall back to Basic
        if r.status_code == 401 and cam_username:
            r.close()
            r = _try_fetch(_DigestAuth(cam_username, cam_password))
            if r.status_code == 401:
                r.close()
                r = _try_fetch((cam_username, cam_password))

        if r.status_code not in (200, 206):
            return jsonify({"error": f"Camera returned HTTP {r.status_code}"}), 502

        content_type = r.headers.get(
            "Content-Type",
            "multipart/x-mixed-replace; boundary=frame"
        )

        def _stream_chunks():
            # Yield raw bytes immediately as they arrive from the camera.
            # Small chunk size ensures MJPEG frame boundaries are flushed
            # to the client right away without waiting for a large buffer.
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    yield chunk

        resp = Response(
            stream_with_context(_stream_chunks()),
            content_type=content_type,
            direct_passthrough=True,
        )
        resp.headers["Cache-Control"]               = "no-cache, no-store, must-revalidate"
        resp.headers["X-Accel-Buffering"]           = "no"
        resp.headers["X-Content-Type-Options"]      = "nosniff"
        resp.headers["Access-Control-Allow-Origin"] = request.host_url.rstrip("/")
        resp.headers["Pragma"]                      = "no-cache"
        resp.headers["Expires"]                     = "0"
        resp.implicit_sequence_conversion           = False
        return resp
    except Exception as e:
        return jsonify({"error": f"Cannot reach camera: {str(e)}"}), 502



@bp.route("/api/camera/audio")
@login_required
def camera_audio_proxy():
    """
    Proxy audio from the camera's audio stream URL through the server.
    Accepts an optional `audio_url` query param; falls back to the camera's
    stream_url with common audio path suffixes tried in order.
    Passes through auth the same way the video proxy does.
    """
    cam_id = request.args.get("cam_id")
    cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()
    if not cam or not cam.stream_url:
        return jsonify({"error": "Camera not found"}), 404

    # Ignore any saved audio_url — it may be stale/wrong (e.g. missing .opus/.wav suffix).
    # Always auto-detect: try /audio.opus, /audio.wav, /audio.aac from the stream base URL.
    # Query param ?audio_url= from client-side probing is still accepted for explicit overrides.
    audio_url = request.args.get("audio_url", "").strip()
    if not audio_url:
        # Derive base URL from stream_url (strip path, keep scheme+host+port)
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(cam.stream_url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        # Include bare /audio — IP Webcam serves audio here too (redirects to .opus/.wav)
        suffixes = ["/audio.opus", "/audio.wav", "/audio.aac", "/audio"]
        for suffix in suffixes:
            candidate = base + suffix
            if not _is_safe_url(candidate):
                continue
            try:
                # Use GET with stream=True and close immediately after headers arrive.
                # HEAD is unreliable on streaming endpoints (many return 404/405 for HEAD
                # even when GET works fine). Reading 0 bytes + close is the safest probe.
                probe = _req.get(candidate, stream=True, timeout=(5, 5), verify=False,
                                 allow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0 (compatible; CatchCatchTV-proxy/2.0)",
                                          "Accept": "audio/*,*/*"})
                status = probe.status_code
                probe.close()
                if status in (200, 206):
                    audio_url = candidate
                    current_app.logger.info(f"[audio-probe] found {candidate} -> HTTP {status}")
                    break
                current_app.logger.debug(f"[audio-probe] {candidate} -> HTTP {status} (skip)")
            except Exception as probe_err:
                current_app.logger.debug(f"[audio-probe] {candidate} -> error: {probe_err}")
                continue
    if not audio_url:
        return jsonify({"error": "No audio URL configured. Go to Settings and add an Audio URL for this camera."}), 404

    # ?check=1 is a pre-flight from the mic button: confirm audio is configured without streaming
    if request.args.get("check") == "1":
        return jsonify({"ok": True, "audio_url": audio_url}), 200

    if not _is_safe_url(audio_url):
        return jsonify({"error": "Invalid audio URL"}), 400

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cam_username = getattr(cam, "cam_username", None) or ""
    cam_password = _decrypt_cam_password(getattr(cam, "cam_password", None) or "")

    def _try_audio(auth_obj):
        return _req.get(
            audio_url,
            stream=True,
            timeout=(10, None),  # connect=10s, read=None (stream indefinitely)
            verify=False,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; CatchCatchTV-proxy/2.0)",
                "Accept": "audio/*,*/*",
            },
            auth=auth_obj,
        )

    try:
        from flask import stream_with_context
        r = _try_audio(None)
        if r.status_code == 401 and cam_username:
            r.close()
            r = _try_audio(_DigestAuth(cam_username, cam_password))
            if r.status_code == 401:
                r.close()
                r = _try_audio((cam_username, cam_password))

        if r.status_code not in (200, 206):
            return jsonify({"error": f"Camera audio returned HTTP {r.status_code}"}), 502

        content_type = r.headers.get("Content-Type", "audio/mpeg")
        resp = Response(
            stream_with_context(r.iter_content(chunk_size=4096)),
            content_type=content_type,
        )
        resp.headers["Cache-Control"]               = "no-cache, no-store, must-revalidate"
        resp.headers["X-Accel-Buffering"]           = "no"
        resp.headers["Access-Control-Allow-Origin"] = request.host_url.rstrip("/")
        resp.headers["Pragma"]                      = "no-cache"
        resp.implicit_sequence_conversion           = False
        return resp
    except Exception as e:
        return jsonify({"error": f"Cannot reach camera audio: {str(e)}"}), 502

@bp.route("/api/camera/probe")
@login_required
def camera_probe():
    """
    Debug endpoint: returns stream metadata.
    For HTTP/HTTPS streams returns the raw first bytes + HTTP status.
    For RTSP/RTMP/RTMPS/ONVIF uses ffprobe to return stream codec info instead,
    since requests.get() cannot speak those protocols.
    """
    cam_id = request.args.get("cam_id")
    cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()
    if not cam or not cam.stream_url:
        return jsonify({"error": "No camera"}), 404
    if not _is_safe_url(cam.stream_url):
        return jsonify({"error": "Blocked"}), 400

    stream_url = cam.stream_url
    scheme = stream_url.split("://")[0].lower() if "://" in stream_url else "http"

    if scheme not in ("http", "https"):
        # Use ffprobe to inspect non-HTTP streams
        ffprobe = shutil.which("ffprobe") or shutil.which("ffmpeg")
        if not ffprobe:
            return jsonify({"error": "ffprobe/ffmpeg not installed on server; cannot probe non-HTTP streams."}), 503

        # Embed credentials if stored
        cam_user = getattr(cam, "cam_username", "") or ""
        cam_pass = _decrypt_cam_password(getattr(cam, "cam_password", "") or "")
        if cam_user and cam_pass:
            try:
                from urllib.parse import urlparse, urlunparse
                p = urlparse(stream_url)
                if not p.username:
                    netloc = f"{cam_user}:{cam_pass}@{p.hostname}"
                    if p.port:
                        netloc += f":{p.port}"
                    stream_url = urlunparse(p._replace(netloc=netloc))
            except Exception:
                pass

        rtsp_flags = ["-rtsp_transport", "tcp"] if scheme == "rtsp" else []
        probe_bin = shutil.which("ffprobe")
        if probe_bin:
            cmd = [
                probe_bin,
                "-v", "quiet",
                "-print_format", "json",
                "-show_streams",
                *rtsp_flags,
                stream_url,
            ]
        else:
            # ffprobe not available, use ffmpeg -i and capture stderr
            cmd = [
                "ffmpeg",
                "-loglevel", "info",
                *rtsp_flags,
                "-i", stream_url,
                "-t", "0",
                "-f", "null", "-",
            ]

        try:
            result = subprocess.run(cmd, timeout=12, capture_output=True, text=True)
            info = result.stdout or result.stderr or "No output from probe."
            return jsonify({
                "protocol": scheme.upper(),
                "probe_info": info[:2000],
                "returncode": result.returncode,
            })
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Probe timed out (12 s). Camera may be unreachable."}), 504
        except Exception as e:
            return jsonify({"error": str(e)}), 502

    # HTTP / HTTPS path — fetch first bytes directly
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        r = _req.get(stream_url, stream=True, timeout=(8, 5), verify=False, allow_redirects=True)
        preview = b""
        for chunk in r.iter_content(chunk_size=512):
            preview += chunk
            if len(preview) >= 500:
                break
        r.close()
        return jsonify({
            "status_code": r.status_code,
            "content_type": r.headers.get("Content-Type", ""),
            "final_url": r.url,
            "preview_hex": preview[:500].hex(),
            "preview_text": preview[:500].decode("utf-8", errors="replace"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@bp.route("/api/camera/snapshot")
@login_required
def camera_snapshot():
    target_user_id = request.args.get("user_id", g.user.id)
    if target_user_id != g.user.id and g.user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    cam = Camera.query.filter_by(user_id=target_user_id).first()
    if not cam or not cam.stream_url:
        return jsonify({"error": "No camera configured"}), 404

    # Block requests to internal/private IPs (SSRF protection)
    if not _is_safe_url(cam.stream_url):
        log_event("SECURITY", f"Blocked SSRF attempt via snapshot: {cam.stream_url}",
                  "CRITICAL", g.user.id, request.remote_addr)
        return jsonify({"error": "Invalid camera URL."}), 400

    stream_url = cam.stream_url
    scheme = stream_url.split("://")[0].lower() if "://" in stream_url else "http"

    # For non-HTTP protocols (RTSP, RTMP, RTMPS, ONVIF) use FFmpeg to grab a
    # single frame, since requests.get() cannot speak these protocols.
    if scheme not in ("http", "https"):
        if not shutil.which("ffmpeg"):
            return jsonify({"error": "FFmpeg is not installed on the server; cannot snapshot non-HTTP streams."}), 503

        # Embed stored credentials into the URL if not already present
        cam_user = getattr(cam, "cam_username", "") or ""
        cam_pass = _decrypt_cam_password(getattr(cam, "cam_password", "") or "")
        if cam_user and cam_pass:
            try:
                from urllib.parse import urlparse, urlunparse
                p = urlparse(stream_url)
                if not p.username:
                    netloc = f"{cam_user}:{cam_pass}@{p.hostname}"
                    if p.port:
                        netloc += f":{p.port}"
                    stream_url = urlunparse(p._replace(netloc=netloc))
            except Exception:
                pass

        rtsp_flags = ["-rtsp_transport", "tcp"] if scheme == "rtsp" else []
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            cmd = [
                "ffmpeg", "-y",
                "-loglevel", "error",
                *rtsp_flags,
                "-i", stream_url,
                "-vframes", "1",
                "-f", "image2",
                tmp_path,
            ]
            result = subprocess.run(cmd, timeout=15, capture_output=True)
            if result.returncode != 0 or not os.path.getsize(tmp_path):
                return jsonify({"error": "FFmpeg could not extract a frame from the stream."}), 502
            with open(tmp_path, "rb") as f:
                jpeg_bytes = f.read()
            return Response(
                jpeg_bytes,
                content_type="image/jpeg",
                headers={"Cache-Control": "no-cache, no-store"},
            )
        except subprocess.TimeoutExpired:
            return jsonify({"error": "FFmpeg snapshot timed out."}), 504
        except Exception as e:
            return jsonify({"error": f"FFmpeg snapshot failed: {str(e)}"}), 502
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    # HTTP / HTTPS path — fetch the stream directly and extract the first JPEG frame
    try:
        r = _req.get(cam.stream_url, stream=True, timeout=(4, 10), verify=False)
        buf = b""
        MAX_BYTES = 256 * 1024

        for chunk in r.iter_content(chunk_size=8192):
            buf += chunk

            start = buf.find(b"\xff\xd8")
            if start != -1:
                end = buf.find(b"\xff\xd9", start + 2)
                if end != -1:
                    jpeg_bytes = buf[start:end + 2]
                    r.close()
                    return Response(
                        jpeg_bytes,
                        content_type="image/jpeg",
                        headers={"Cache-Control": "no-cache, no-store"},
                    )

            if len(buf) > MAX_BYTES:
                break

        r.close()
        return jsonify({"error": "No JPEG frame found in camera stream"}), 502

    except Exception as e:
        return jsonify({"error": f"Cannot reach camera: {str(e)}"}), 502




# ═══════════════════════════════════════════════════════════════════
# LOCAL NETWORK BRIDGE RELAY
# Allows cameras on private networks (192.168.x.x, 10.x.x.x, etc.)
# to stream through CatchCatchTV without port forwarding.
#
# Architecture:
#   User runs bridge.py on any PC on their home network.
#   bridge.py reads the local RTSP via FFmpeg → converts to MJPEG frames
#   → streams frames to /api/camera/bridge/intake/<token> (outbound POST).
#   Browser fetches /api/camera/bridge/relay/<cam_id> which re-streams
#   those frames as MJPEG.  No ports need to be opened on the home router.
# ═══════════════════════════════════════════════════════════════════

import hmac as _hmac
import hashlib as _hashlib
import queue as _q_module

# In-memory latest-frame store: token -> {"frame": bytes, "seq": int, "ts": float}
_bridge_frames: dict = {}
_bridge_frames_lock = threading.Lock()
# Tokens of bridges actively streaming (intake request in-flight), even before first frame
_bridge_active: set = set()
_bridge_active_lock = threading.Lock()


def _make_bridge_token(cam_id) -> str:
    """Derive a stable, revocation-less bridge token from SECRET_KEY + cam_id."""
    from flask import current_app
    key = current_app.config["SECRET_KEY"].encode()
    return _hmac.new(key, f"bridge:{cam_id}".encode(), _hashlib.sha256).hexdigest()[:40]


@bp.route("/api/camera/bridge/token")
@login_required
def bridge_get_token():
    """Return the bridge auth token for a camera (used to pre-fill bridge.py)."""
    cam_id = request.args.get("cam_id")
    cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()
    if not cam:
        return jsonify({"error": "Camera not found"}), 404
    return jsonify({"token": _make_bridge_token(cam_id), "cam_id": cam_id})


@bp.route("/api/camera/bridge/status/<cam_id>")
@login_required
def bridge_status(cam_id):
    """Check whether a bridge is currently connected for this camera."""
    cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()
    if not cam:
        return jsonify({"error": "Camera not found"}), 404
    token = _make_bridge_token(cam_id)
    with _bridge_frames_lock:
        entry = _bridge_frames.get(token)
    frame_fresh = bool(entry and (time.time() - entry["ts"]) < 10)
    with _bridge_active_lock:
        intake_live = token in _bridge_active
    connected = frame_fresh or intake_live
    return jsonify({"connected": connected})


@bp.route("/api/camera/bridge/intake/<token>", methods=["POST"])
@csrf.exempt
def bridge_intake(token):
    """
    The bridge.py script on the user's home network POSTs a chunked MJPEG
    stream here.  No session cookie is needed — the HMAC token is the credential.
    """
    cam_id = request.args.get("cam_id")
    if not cam_id:
        return jsonify({"error": "cam_id query param required"}), 400

    # Constant-time token verification to prevent timing attacks
    try:
        expected = _make_bridge_token(cam_id)
    except Exception:
        return jsonify({"error": "Server config error"}), 500
    if not _hmac.compare_digest(token, expected):
        return jsonify({"error": "Invalid token"}), 403

    cam = Camera.query.filter_by(id=cam_id).first()
    if not cam:
        return jsonify({"error": "Camera not found"}), 404

    buf = b""
    seq = 0
    with _bridge_active_lock:
        _bridge_active.add(token)
    try:
        for chunk in request.stream:
            buf += chunk
            # Parse JPEG frames (SOI=\xff\xd8 … EOI=\xff\xd9) out of the byte stream
            while True:
                start = buf.find(b"\xff\xd8")
                if start == -1:
                    if len(buf) > 131072:
                        buf = buf[-2048:]  # discard junk — keep last 2KB in case SOI split
                    break
                end = buf.find(b"\xff\xd9", start + 2)
                if end == -1:
                    break  # frame not complete yet
                frame = buf[start:end + 2]
                buf = buf[end + 2:]
                seq += 1
                with _bridge_frames_lock:
                    _bridge_frames[token] = {"frame": frame, "seq": seq, "ts": time.time()}
    finally:
        with _bridge_active_lock:
            _bridge_active.discard(token)
        # Remove entry only if it's still ours (another intake may have replaced it)
        with _bridge_frames_lock:
            entry = _bridge_frames.get(token)
            if entry and entry.get("seq") == seq:
                _bridge_frames.pop(token, None)

    return "", 204


@bp.route("/api/camera/bridge/relay/<cam_id>")
@login_required
def bridge_relay(cam_id):
    """
    Browser fetches this endpoint as an MJPEG stream — identical to the normal
    camera proxy but sourced from the in-memory bridge frame buffer.
    """
    cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()
    if not cam:
        return jsonify({"error": "Camera not found"}), 404

    token = _make_bridge_token(cam_id)
    with _bridge_frames_lock:
        entry = _bridge_frames.get(token)
    if not entry or (time.time() - entry["ts"]) > 10:
        return jsonify({"error": "Bridge not connected. Run bridge.py on your home network."}), 503

    def generate():
        last_seq = -1
        stale_ticks = 0
        while stale_ticks < 150:          # 150 × 0.1 s = 15 s timeout with no new frames
            with _bridge_frames_lock:
                entry = _bridge_frames.get(token)
            if not entry:
                break                     # bridge disconnected
            if entry["seq"] != last_seq:
                # Always grab the absolute latest frame — skip any queued ones
                # so the browser never plays back stale footage
                with _bridge_frames_lock:
                    entry = _bridge_frames.get(token)
                if not entry:
                    break
                last_seq = entry["seq"]
                stale_ticks = 0
                yield (
                    b"--frame\r\n"
                    b"Content-Type: image/jpeg\r\n\r\n"
                    + entry["frame"]
                    + b"\r\n"
                )
            else:
                stale_ticks += 1
                time.sleep(0.033)  # ~30fps poll instead of 10fps

    from flask import stream_with_context
    return Response(
        stream_with_context(generate()),
        content_type="multipart/x-mixed-replace; boundary=frame",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@bp.route("/api/camera/bridge/download/<cam_id>")
@login_required
def bridge_download(cam_id):
    """Generate and serve a pre-configured bridge.py script for download."""
    cam = Camera.query.filter_by(id=cam_id, user_id=g.user.id).first()
    if not cam:
        return jsonify({"error": "Camera not found"}), 404

    token = _make_bridge_token(cam_id)
    server_url = request.host_url.rstrip("/")

    # Build the bridge script with credentials baked in
    # Use string concatenation (not f-strings) to avoid UUID hyphens
    # being misinterpreted as numeric expressions by Python.
    NL = chr(10)
    Q3 = chr(34) * 3
    body = (
        "#!/usr/bin/env python3" + NL
        + Q3 + NL
        + "CatchCatchTV Bridge - run on any PC that can reach your local camera." + NL
        + "Requirements: Python 3.8+, FFmpeg, requests" + NL
        + "Install:  pip install requests" + NL
        + "Usage:    python bridge.py" + NL
        + Q3 + NL
        + "import subprocess, sys, time" + NL
        + "import requests" + NL + NL
    )
    body += "SERVER_URL  = \"" + str(server_url) + "\"" + NL
    body += "CAM_ID      = \"" + str(cam_id) + "\"" + NL
    body += "TOKEN       = \"" + str(token) + "\"" + NL
    body += "STREAM_URL  = \"" + str(cam.stream_url) + "\"" + NL
    body += (
        "FPS         = 10" + NL
        + "RECONNECT_S = 5" + NL + NL + NL
        + "def iter_jpeg_frames(stream):" + NL
        + "    buf = b\"\"" + NL
        + "    while True:" + NL
        + "        chunk = stream.read(65536)" + NL
        + "        if not chunk:" + NL
        + "            break" + NL
        + "        buf += chunk" + NL
        + "        while True:" + NL
        + "            s = buf.find(b\"\\xff\\xd8\")" + NL
        + "            if s == -1:" + NL
        + "                if len(buf) > 1_048_576:" + NL
        + "                    buf = buf[-4096:]" + NL
        + "                break" + NL
        + "            e = buf.find(b\"\\xff\\xd9\", s + 2)" + NL
        + "            if e == -1:" + NL
        + "                break" + NL
        + "            yield buf[s:e + 2]" + NL
        + "            buf = buf[e + 2:]" + NL + NL + NL
        + "def find_ffmpeg():" + NL
        + "    \"\"\"Find ffmpeg: check same folder as script first, then PATH.\"\"\"" + NL
        + "    import os, shutil" + NL
        + "    script_dir = os.path.dirname(os.path.abspath(__file__))" + NL
        + "    local = os.path.join(script_dir, 'ffmpeg.exe')" + NL
        + "    if os.path.isfile(local):" + NL
        + "        print('[bridge] Using ffmpeg from script folder: ' + local)" + NL
        + "        return local" + NL
        + "    found = shutil.which('ffmpeg')" + NL
        + "    if found:" + NL
        + "        return found" + NL
        + "    print('[bridge] ERROR: ffmpeg not found.')" + NL
        + "    print('[bridge] Easy fix: download ffmpeg.exe and put it in the same folder as bridge.py.')" + NL
        + "    print('[bridge] Download: https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip')" + NL
        + "    print('[bridge] Extract the zip, go into the bin folder, copy ffmpeg.exe next to bridge.py.')" + NL
        + "    sys.exit(1)" + NL + NL + NL
        + "def run_bridge():" + NL
        + "    ffmpeg_bin = find_ffmpeg()" + NL
        + "    session = requests.Session()" + NL
        + "    intake_url = SERVER_URL + \"/api/camera/bridge/intake/\" + TOKEN + \"?cam_id=\" + CAM_ID" + NL
        + "    while True:" + NL
        + "        print(\"[bridge] Connecting to \" + STREAM_URL + \" ...\")" + NL
        + "        cmd = [ffmpeg_bin," + NL
        + "            \"-loglevel\", \"warning\"," + NL
        + "            \"-fflags\", \"nobuffer+discardcorrupt\"," + NL
        + "            \"-flags\", \"low_delay\"," + NL
        + "            *([\"-rtsp_transport\", \"tcp\"] if STREAM_URL.startswith(\"rtsp://\") else [])," + NL
        + "            \"-i\", STREAM_URL," + NL
        + "            \"-an\"," + NL
        + "            \"-vf\", \"fps=\" + str(FPS)," + NL
        + "            \"-f\", \"image2pipe\"," + NL
        + "            \"-vcodec\", \"mjpeg\"," + NL
        + "            \"-q:v\", \"5\"," + NL
        + "            \"-vsync\", \"drop\"," + NL
        + "            \"-\"]" + NL
        + "        try:" + NL
        + "            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=sys.stderr)" + NL
        + "        except FileNotFoundError:" + NL
        + "            print(\"[bridge] ERROR: ffmpeg not found.\")" + NL
        + "            sys.exit(1)" + NL
        + "        print(\"[bridge] Streaming to \" + SERVER_URL + \" ...\")" + NL
        + "        print(\"[bridge] Waiting for first video frame — this can take 5-15 seconds...\")" + NL
        + "        try:" + NL
        + "            session.post(intake_url, data=iter_jpeg_frames(proc.stdout), headers={\"Content-Type\": \"application/octet-stream\", \"Transfer-Encoding\": \"chunked\"}, stream=True, timeout=None)" + NL
        + "        except KeyboardInterrupt:" + NL
        + "            print(\"[bridge] Stopped.\")" + NL
        + "            proc.terminate()" + NL
        + "            sys.exit(0)" + NL
        + "        except Exception as ex:" + NL
        + "            print(\"[bridge] Connection error: \" + str(ex))" + NL
        + "        finally:" + NL
        + "            try:" + NL
        + "                proc.terminate()" + NL
        + "                proc.wait(timeout=3)" + NL
        + "            except Exception:" + NL
        + "                pass" + NL
        + "        print(\"[bridge] Reconnecting in \" + str(RECONNECT_S) + \"s ...\")" + NL
        + "        time.sleep(RECONNECT_S)" + NL + NL + NL
        + "if __name__ == \"__main__\":" + NL
        + "    run_bridge()" + NL
    )
    script = body

    return Response(
        script,
        mimetype="text/x-python",
        headers={"Content-Disposition": "attachment; filename=bridge.py"},
    )

_ffmpeg_exe_cache: bytes | None = None
_ffmpeg_exe_lock = threading.Lock()

@bp.route("/api/ffmpeg/download")
@login_required
def ffmpeg_download():
    """Fetch ffmpeg-release-essentials.zip from gyan.dev, extract ffmpeg.exe, serve it directly.
    The exe is cached in memory after the first fetch so subsequent downloads are instant."""
    global _ffmpeg_exe_cache
    import urllib.request as _urllib_req
    import zipfile as _zipfile
    import io as _io

    FFMPEG_ZIP_URL = "https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip"

    with _ffmpeg_exe_lock:
        if _ffmpeg_exe_cache is None:
            try:
                with _urllib_req.urlopen(FFMPEG_ZIP_URL, timeout=120) as resp:
                    zip_data = resp.read()
            except Exception as ex:
                return jsonify({"error": f"Could not fetch FFmpeg: {ex}"}), 502

            try:
                with _zipfile.ZipFile(_io.BytesIO(zip_data)) as zf:
                    exe_name = next(n for n in zf.namelist() if n.endswith("/bin/ffmpeg.exe"))
                    _ffmpeg_exe_cache = zf.read(exe_name)
            except Exception as ex:
                return jsonify({"error": f"Could not extract ffmpeg.exe: {ex}"}), 500

        exe_bytes = _ffmpeg_exe_cache

    return Response(
        exe_bytes,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=ffmpeg.exe"},
    )


@bp.route("/privacy")
def privacy():
    return render_template("privacy.html")

@bp.route("/terms")
def terms():
    return render_template("terms.html")
