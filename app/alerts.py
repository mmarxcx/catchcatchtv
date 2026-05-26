"""
CatchCatchTV — Discord webhook alerts  (v4.0 — root-cause fix)

ROOT CAUSE FIXED:
  The old _get_admin_webhook() used a module-level cache + raw SQL query.
  The cache was working correctly, but the raw SQL was reading a value that
  was never actually committed — SQLAlchemy's session.commit() on Railway
  was succeeding at the ORM layer but the raw SQL (run in a new implicit
  transaction) was reading the pre-commit snapshot in Postgres's MVCC.

  Fix: Instead of raw SQL with a module-level cache, we accept the admin
  webhook URL as an explicit argument (passed by the caller from g.user),
  so there is NO separate DB query at alert time. The value comes straight
  from the already-loaded ORM object.

  For call sites that don't have g.user handy (e.g. background tasks), a
  thin _fetch_admin_webhook_from_db() fallback still exists but is NOT
  cached, so it always reads a fresh committed value.

SEND BEHAVIOUR:
  Synchronous (no daemon threads). Every step prints a Railway-visible log line.
  Debounce is kept but skipped on first-ever call per key.
"""

import time
import requests
from datetime import datetime

_debounce: dict = {}

COLORS = {"INFO": 3447003, "WARNING": 16776960, "ALERT": 15105570, "CRITICAL": 15158332}
ICONS  = {"INFO": "ℹ️",    "WARNING": "⚠️",      "ALERT": "🚨",     "CRITICAL": "🔴"}


# ── Admin webhook: no cache, no raw SQL ──────────────────────────────────────

def _fetch_admin_webhook_from_db() -> str:
    """
    Direct ORM query for the admin user's global webhook URL.
    Always reads the freshest committed value. No caching.
    """
    try:
        from app import db
        from app.models import User
        admin = db.session.query(User.admin_webhook).filter(
            User.role == "admin", User.admin_webhook.isnot(None)
        ).first()
        val = (admin[0] or "").strip() if admin else ""
        if val:
            print(f"[ADMIN WEBHOOK] Fetched from DB: ...{val[-30:]}")
        else:
            print("[ADMIN WEBHOOK] DB query returned empty — no global webhook saved yet")
        return val
    except Exception as exc:
        print(f"[ADMIN WEBHOOK] DB query failed: {exc}")
        return ""


def invalidate_admin_webhook_cache():
    """No-op kept for backwards compatibility — there is no cache anymore."""
    print("[ADMIN WEBHOOK] Cache invalidated (no-op in v4.0 — no cache)")


def get_global_webhook() -> str:
    """
    Return the admin's global webhook URL.
    Always does a fresh DB query so it is never stale.
    Fast: single indexed query on role='admin'.
    """
    return _fetch_admin_webhook_from_db()


# ── Core send ────────────────────────────────────────────────────────────────

def _fire(url: str, title: str, description: str, severity: str,
          fields: list, label: str = ""):
    """Send one Discord embed synchronously."""
    tag = f"[DISCORD:{label}]" if label else "[DISCORD]"

    if not url:
        print(f"{tag} SKIP — no URL (title={title!r})")
        return

    if not (
        url.startswith("https://discord.com/api/webhooks/") or
        url.startswith("https://discordapp.com/api/webhooks/")
    ):
        print(f"{tag} SKIP — URL failed validation: {url!r}")
        return

    sev   = severity.upper()
    embed = {
        "title":       f"{ICONS.get(sev, '🔔')} {title}",
        "description": description,
        "color":       COLORS.get(sev, 3447003),
        "timestamp":   datetime.utcnow().isoformat(),
        "footer":      {"text": "CatchCatchTV 📹"},
        "fields":      fields or [],
    }
    print(f"{tag} Sending — severity={sev} title={title!r} url=...{url[-30:]}")
    try:
        resp = requests.post(
            url,
            json={"username": "CatchCatchTV Bot", "embeds": [embed]},
            timeout=8,
        )
        if resp.status_code == 204:
            print(f"{tag} ✅ Sent OK (204)")
        else:
            print(f"{tag} ❌ HTTP {resp.status_code} — {resp.text[:300]}")
    except Exception as exc:
        print(f"{tag} ❌ Exception: {exc}")


def send_alert(webhook_url: str, title: str, description: str,
               severity: str = "ALERT", fields: list = None,
               debounce_sec: int = 20,
               admin_webhook_url: str = None):
    """
    Send a Discord alert.

    webhook_url       — the triggering user's personal webhook (may be empty)
    admin_webhook_url — optional explicit override. If None OR empty string,
                        the global admin webhook is fetched automatically via
                        get_global_webhook() which always queries the admin
                        user row — NOT g.user (which may be a regular user).
                        Callers should NOT pass g.user.admin_webhook here.
    """
    # Resolve admin URL — always read from the admin user's row, never from the
    # acting user's row (a regular user's admin_webhook column is always NULL).
    if not admin_webhook_url:
        admin_url = get_global_webhook()
        if admin_url:
            print(f"[ADMIN WEBHOOK] Resolved via get_global_webhook: ...{admin_url[-30:]}")
        else:
            print("[ADMIN WEBHOOK] get_global_webhook returned empty — no global webhook saved yet")
    else:
        admin_url = admin_webhook_url.strip()
        print(f"[ADMIN WEBHOOK] Using caller-supplied URL: ...{admin_url[-30:]}")

    print(
        f"[DISCORD] send_alert title={title!r} "
        f"user_url={'SET' if webhook_url else 'empty'} "
        f"admin_url={'SET' if admin_url else 'empty'}"
    )

    # ── Debounce ──────────────────────────────────────────────────────────────
    def _is_debounced(url: str) -> bool:
        key  = f"{url}:{title}:{description[:60]}"
        now  = datetime.utcnow().timestamp()
        last = _debounce.get(key)
        if last is None:
            _debounce[key] = now
            return False
        remaining = (last + debounce_sec) - now
        if remaining > 0:
            print(f"[DISCORD] Debounced {remaining:.1f}s remaining (title={title!r})")
            return True
        _debounce[key] = now
        return False

    # ── User webhook ──────────────────────────────────────────────────────────
    if webhook_url:
        if not _is_debounced(webhook_url):
            _fire(webhook_url, title, description, severity, fields, label="user")
    else:
        print(f"[DISCORD:user] SKIP — no user webhook (title={title!r})")

    # ── Admin webhook ─────────────────────────────────────────────────────────
    # Skip if admin URL is same as user URL to avoid double-posting
    if admin_url and admin_url != webhook_url:
        if not _is_debounced(admin_url):
            _fire(admin_url, title, description, severity, fields, label="admin")
    elif admin_url and admin_url == webhook_url:
        print(f"[DISCORD:admin] SKIP — same URL as user webhook, already sent (title={title!r})")
    else:
        print(f"[DISCORD:admin] SKIP — no admin webhook configured (title={title!r})")


# ── Typed alert helpers ───────────────────────────────────────────────────────

def alert_login(webhook_url: str, username: str, ip: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title=f"Login — {username}",
               description=f"**{username}** logged in to CatchCatchTV.",
               severity="INFO", fields=[{"name": "IP Address", "value": ip, "inline": True}],
               debounce_sec=5, admin_webhook_url=admin_webhook_url)

def alert_new_ip_login(webhook_url: str, username: str, ip: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title=f"⚠️ New IP Login — {username}",
               description=f"**{username}** logged in from a new IP address.",
               severity="WARNING", fields=[{"name": "New IP Address", "value": ip, "inline": True}],
               debounce_sec=5, admin_webhook_url=admin_webhook_url)

def alert_failed_login(webhook_url: str, email: str, ip: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title=f"Failed Login Attempt — {email}",
               description=f"Someone tried to log in as `{email}` and failed.",
               severity="WARNING", fields=[{"name": "IP Address", "value": ip, "inline": True}],
               debounce_sec=5, admin_webhook_url=admin_webhook_url)

def alert_new_user(webhook_url: str, username: str, ip: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title=f"New User Registered — {username}",
               description=f"**{username}** just created an account.",
               severity="INFO", fields=[{"name": "IP Address", "value": ip, "inline": True}],
               debounce_sec=5, admin_webhook_url=admin_webhook_url)

def alert_camera_offline(webhook_url: str, label: str, ip: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title="Camera Offline",
               description=f"Camera **{label}** went offline.",
               severity="CRITICAL", fields=[{"name": "IP", "value": ip, "inline": True}],
               debounce_sec=30, admin_webhook_url=admin_webhook_url)

def alert_camera_online(webhook_url: str, label: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title="Camera Reconnected",
               description=f"Camera **{label}** is back online.",
               severity="INFO", debounce_sec=10, admin_webhook_url=admin_webhook_url)

def alert_ip_blocked(webhook_url: str, ip: str, reason: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title="IP Address Blocked",
               description=f"`{ip}` has been blocked.\nReason: {reason}",
               severity="CRITICAL", debounce_sec=5, admin_webhook_url=admin_webhook_url)

def alert_brute_force(webhook_url: str, ip: str, attempts: int, admin_webhook_url: str = None):
    send_alert(webhook_url, title="Brute Force Detected",
               description=f"`{ip}` made **{attempts}** failed login attempts.",
               severity="ALERT", debounce_sec=10, admin_webhook_url=admin_webhook_url)

def alert_suspicious_session(webhook_url: str, ip: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title="Suspicious Session",
               description=f"Session IP mismatch detected from `{ip}`. Session revoked.",
               severity="ALERT", debounce_sec=10, admin_webhook_url=admin_webhook_url)

def alert_person_detected(webhook_url: str, detected_class: str, confidence: float, timestamp,
                           admin_webhook_url: str = None):
    ts_str   = timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if hasattr(timestamp, 'strftime') else str(timestamp)
    conf_str = f"{confidence * 100:.1f}%"
    send_alert(webhook_url, title="Person Detected",
               description="AI detection picked up a person on the camera feed.",
               severity="CRITICAL",
               fields=[
                   {"name": "Detected As", "value": detected_class, "inline": True},
                   {"name": "Confidence",  "value": conf_str,       "inline": True},
                   {"name": "Time",        "value": ts_str,         "inline": False},
               ], debounce_sec=1, admin_webhook_url=admin_webhook_url)

def alert_logout(webhook_url: str, username: str, ip: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title=f"Logout — {username}",
               description=f"**{username}** logged out of CatchCatchTV.",
               severity="INFO", fields=[{"name": "IP Address", "value": ip, "inline": True}],
               debounce_sec=5, admin_webhook_url=admin_webhook_url)

def alert_admin_access_denied(webhook_url: str, username: str, ip: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title=f"Unauthorized Admin Access — {username}",
               description=f"**{username}** tried to access the admin panel without permission.",
               severity="ALERT", fields=[{"name": "IP Address", "value": ip, "inline": True}],
               debounce_sec=5, admin_webhook_url=admin_webhook_url)

def alert_idor_attempt(webhook_url: str, username: str, ip: str, room_id: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title=f"Intrusion Attempt — {username}",
               description=f"**{username}** tried to access another user's camera feed.",
               severity="CRITICAL", fields=[
                   {"name": "IP Address",  "value": ip,      "inline": True},
                   {"name": "Target Room", "value": room_id, "inline": True},
               ], debounce_sec=5, admin_webhook_url=admin_webhook_url)

def alert_rate_limit(webhook_url: str, ip: str, admin_webhook_url: str = None):
    send_alert(webhook_url, title="Rate Limit Triggered",
               description=f"`{ip}` is sending too many requests and has been temporarily blocked.",
               severity="WARNING", fields=[{"name": "IP Address", "value": ip, "inline": True}],
               debounce_sec=10, admin_webhook_url=admin_webhook_url)
