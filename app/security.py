import secrets
import hashlib
import ipaddress
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import request, jsonify, redirect, g, current_app
from app import db
from app.models import UserSession, BlockedIP, WhitelistedIP, SecuritySetting, User

# ─────────────────────────────────────────────────────────────
# RATE LIMITING
#
# We use the database for rate limiting instead of an in-memory
# dict. This means rate limits survive server restarts and work
# correctly even if Railway spins up multiple workers.
# ─────────────────────────────────────────────────────────────

SESSION_SLIDE_THRESHOLD = 1800  # seconds

DEFAULT_SECURITY_SETTINGS = {
    "auto_block_enabled": True,
    "failed_login_threshold": 5,
    "failed_login_window": 60,
    "auto_block_minutes": 60,
    "live_refresh_seconds": 30,
    "maintenance_mode": False,
    "lockdown_mode": False,
    "honeypot_auto_block": True,
}


def normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return ""


def parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("1", "true", "yes", "on")


def get_security_setting(key: str, default=None):
    default = DEFAULT_SECURITY_SETTINGS.get(key, default)
    rec = db.session.get(SecuritySetting, key)
    if not rec:
        return default
    if isinstance(default, bool):
        return parse_bool(rec.value)
    if isinstance(default, int):
        try:
            return int(rec.value)
        except (TypeError, ValueError):
            return default
    return rec.value


def set_security_setting(key: str, value):
    rec = db.session.get(SecuritySetting, key)
    text_value = str(value).lower() if isinstance(value, bool) else str(value)
    if not rec:
        db.session.add(SecuritySetting(key=key, value=text_value))
    else:
        rec.value = text_value


def get_security_settings() -> dict:
    return {key: get_security_setting(key, default) for key, default in DEFAULT_SECURITY_SETTINGS.items()}


def is_ip_whitelisted(ip: str) -> bool:
    ip = normalize_ip(ip)
    return bool(ip and WhitelistedIP.query.filter_by(ip_address=ip).first())


def is_rate_limited(ip: str, limit: int = 10, window: int = 60) -> bool:
    """
    Returns True if the IP has exceeded `limit` requests in the last `window` seconds.
    Uses the RateLimit table in the database so limits persist across restarts.
    """
    from app.models import RateLimit

    now    = datetime.utcnow()
    cutoff = now - timedelta(seconds=window)

    # Clean up old entries for this IP
    RateLimit.query.filter(
        RateLimit.ip_address == ip,
        RateLimit.timestamp  <  cutoff
    ).delete(synchronize_session=False)

    # Count recent hits
    count = RateLimit.query.filter(
        RateLimit.ip_address == ip,
        RateLimit.timestamp  >= cutoff
    ).count()

    # Record this hit
    db.session.add(RateLimit(ip_address=ip, timestamp=now))

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()

    return count >= limit


def is_ip_blocked(ip: str) -> bool:
    ip = normalize_ip(ip)
    if not ip or is_ip_whitelisted(ip):
        return False
    cache_key = f"_ip_blocked_{ip}"
    cached = getattr(g, cache_key, None)
    if cached is not None:
        return cached

    rec = BlockedIP.query.filter_by(ip_address=ip).first()
    if not rec:
        setattr(g, cache_key, False)
        return False
    if rec.blocked_until < datetime.utcnow():
        db.session.delete(rec)
        db.session.commit()
        setattr(g, cache_key, False)
        return False
    setattr(g, cache_key, True)
    return True


def block_ip(ip: str, minutes: int = 15, reason: str = "Suspicious activity", created_by: str = None):
    from app.logger import log_event
    ip = normalize_ip(ip)
    if not ip or is_ip_whitelisted(ip):
        return False
    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    until    = datetime.utcnow() + timedelta(days=3650 if int(minutes) <= 0 else 0, minutes=max(int(minutes), 0))
    if existing:
        existing.blocked_until = until
        existing.reason        = reason
        existing.created_by    = created_by
    else:
        db.session.add(BlockedIP(ip_address=ip, blocked_until=until, reason=reason, created_by=created_by))
    db.session.commit()
    log_event("NETWORK", f"IP blocked {minutes}m: {reason}", "CRITICAL", ip=ip)
    return True


def failed_login_count(ip: str, window: int) -> int:
    from app.models import Log
    ip = normalize_ip(ip)
    cutoff = datetime.utcnow() - timedelta(seconds=window)
    return Log.query.filter(
        Log.ip_address == ip,
        Log.event_type == "AUTH",
        Log.severity == "WARNING",
        Log.timestamp >= cutoff,
    ).count()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id: str, ip: str, ua: str) -> str:
    # Removed IP check — Render's proxy changes IP between requests
    for s in UserSession.query.filter_by(user_id=user_id, is_revoked=False).all():
        s.is_revoked = True
    token   = secrets.token_urlsafe(48)
    timeout = current_app.config["SESSION_INACTIVITY_SECONDS"]
    db.session.add(UserSession(
        user_id       = user_id,
        session_token = _hash(token),
        ip_address    = ip,
        user_agent    = (ua or "")[:256],
        expires_at    = datetime.utcnow() + timedelta(seconds=timeout),
    ))
    db.session.commit()
    return token


def validate_session(token: str, ip: str):
    if not token:
        return None
    sess = UserSession.query.filter_by(session_token=_hash(token), is_revoked=False).first()
    if not sess:
        return None
    now = datetime.utcnow()
    if sess.expires_at < now:
        sess.is_revoked = True
        db.session.commit()
        return None

    timeout = current_app.config["SESSION_INACTIVITY_SECONDS"]
    time_remaining = (sess.expires_at - now).total_seconds()
    if time_remaining < SESSION_SLIDE_THRESHOLD:
        sess.expires_at  = now + timedelta(seconds=timeout)
        sess.last_active = now
        db.session.commit()
    if sess.ip_address and sess.ip_address != ip:
        from app.logger import log_event
        log_event("SESSION", f"IP mismatch: orig={sess.ip_address} now={ip}",
                "WARNING", sess.user_id, ip)

    return sess


def revoke_session(token: str):
    sess = UserSession.query.filter_by(session_token=_hash(token)).first()
    if sess:
        sess.is_revoked = True
        db.session.commit()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip    = request.remote_addr
        token = request.cookies.get("cctv_session")
        if is_ip_blocked(ip):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Your IP is blocked."}), 403
            return redirect("/login?reason=blocked")
        sess = validate_session(token, ip) if token else None
        if not sess:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Session expired."}), 401
            return redirect("/login?reason=expired")
        user = db.session.get(User, sess.user_id)
        if not user or not user.is_active:
            return redirect("/login")
        if user.must_reset_password and request.path not in ("/settings", "/api/account/password", "/api/logout", "/logout"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Password reset required."}), 403
            return redirect("/settings?reason=password-reset-required")
        g.user    = user
        g.session = sess
        return f(*args, **kwargs)
    return decorated
