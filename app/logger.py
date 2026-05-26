import json
import queue
import re
from datetime import datetime, timezone
from typing import Optional
from flask import request
from app import db
from app.models import Log

_subscribers: dict = {}

def _get_device_info() -> str:
    """Safely extracts the Browser and Operating System from the HTTP request."""
    try:
        ua_string = request.headers.get('User-Agent', '')
        if not ua_string:
            return "Unknown Device/OS"

        os_name = "Unknown OS"
        if 'Windows' in ua_string: os_name = "Windows"
        elif 'Mac OS X' in ua_string: os_name = "macOS"
        elif 'Linux' in ua_string: os_name = "Linux"
        elif 'Android' in ua_string: os_name = "Android"
        elif 'iPhone' in ua_string or 'iPad' in ua_string: os_name = "iOS"

        browser = "Unknown Browser"
        if 'Edg' in ua_string: browser = "Edge"
        elif 'Chrome' in ua_string: browser = "Chrome"
        elif 'Safari' in ua_string and 'Chrome' not in ua_string: browser = "Safari"
        elif 'Firefox' in ua_string: browser = "Firefox"
        elif 'Opera' in ua_string or 'OPR' in ua_string: browser = "Opera"

        return f"{browser} on {os_name}"
    except Exception:
        return "Unknown Device/OS"

def _formalize_log(description: str, event_type: str, severity: str, user_id: Optional[str], ip: Optional[str]) -> str:
    d = description.strip()
    device_info = _get_device_info()
    ip_str = ip or "Unknown IP"
    username = "System"
    
    if user_id:
        try:
            from app.models import User
            user = db.session.get(User, user_id)
            if user: username = user.username
        except Exception: pass

    user_match = re.search(r'(?:user(?:name)?[:\s]+|New user registered:\s*|Failed login:\s*)([^\s(,]+)', d, re.I)
    extracted_target = user_match.group(1) if user_match else username

    if 'Person detected' in d:
        conf_match = re.search(r'\((\d+)%\)', d)
        conf_str = conf_match.group(1) if conf_match else "XX"
        msg = f"AI Detection alert: Person identified on camera feed with {conf_str}% confidence."
    elif 'Object detected' in d:
        obj_match = re.search(r'Object detected:\s*(.+?)\s*\((\d+)%\)', d)
        obj = obj_match.group(1).capitalize() if obj_match else "An object"
        conf = obj_match.group(2) if obj_match else "XX"
        msg = f"AI Detection notification: {obj} identified in frame with {conf}% confidence."
    elif 'Login from' in d:
        msg = f"Successful authentication for user '{username}' from IP [{ip_str}] using [{device_info}]."
    elif 'Failed login' in d:
        if any(char in extracted_target for char in ["'", '"', "--", ";", "="]):
            msg = f"Critical SQL injection attempt blocked on login field from IP [{ip_str}]. Payload: [{extracted_target}]. Device: [{device_info}]."
        else:
            msg = f"Failed authentication attempt for account '{extracted_target}' from IP [{ip_str}] using [{device_info}]."
    elif 'New user registered' in d:
        msg = f"New account provisioned for user '{extracted_target}' from IP [{ip_str}] using [{device_info}]."
    elif 'Password changed' in d:
        msg = f"Security credentials successfully modified for user '{username}' from IP [{ip_str}]."
    elif 'promoted to admin' in d:
        msg = f"Privilege escalation: User '{extracted_target}' promoted to Administrator role by '{username}'."
    elif 'Too many failures' in d or 'Brute force' in d:
        msg = f"Brute force mitigation activated. IP [{ip_str}] has been temporarily restricted due to excessive failed authentications. Device: [{device_info}]."
    elif 'logged out' in d.lower():
        msg = f"Session terminated successfully for user '{username}' from IP [{ip_str}]."
    elif 'Session expired' in d or 'expired' in d.lower():
        msg = f"Session token invalidated due to inactivity timeout for user '{username}'."
    elif 'Camera updated' in d:
        msg = f"Camera configuration parameters updated by user '{username}'."
    elif 'Logs cleared' in d and 'Admin' in d:
        msg = f"System maintenance: Global activity logs purged securely by Administrator '{username}'."
    elif 'Logs cleared' in d:
        msg = f"User maintenance: Personal activity logs purged securely by user '{username}'."
    elif 'Webhook updated' in d:
        msg = f"External integration: Discord webhook URL modified by user '{username}'."
    elif 'unblocked IP' in d and ip:
        msg = f"Access control: IP [{ip}] removed from the restriction blocklist by Administrator '{username}'."
    elif 'Rate limit' in d:
        msg = f"Traffic anomaly: Rate limiting applied to IP [{ip_str}] due to excessive request volume."
    elif 'IDOR attempt' in d:
        room = re.search(r'room\s+(\S+)', d)
        room_id = room.group(1) if room else 'Unknown'
        msg = f"Unauthorized cross-tenant access (IDOR) attempt blocked. User '{username}' attempted to access private room [{room_id}] from IP [{ip_str}]."
    elif 'Display alias modification' in d:
        msg = f"Account settings updated: {d}"
    else:
        msg = f"System event logged: {d}. Target: [{username}] | IP: [{ip_str}] | Device: [{device_info}]."

    return f"Goodness Gracious! {msg}"

def subscribe(user_id: str) -> queue.Queue:
    q: queue.Queue = queue.Queue(maxsize=200)
    _subscribers.setdefault(user_id, []).append(q)
    return q

def unsubscribe(user_id: str, q: queue.Queue):
    if user_id in _subscribers:
        try:
            _subscribers[user_id].remove(q)
        except ValueError:
            pass

def push_to_user(user_id: str, data: dict):
    dead = []
    for q in _subscribers.get(user_id, []):
        try:
            q.put_nowait(data)
        except queue.Full:
            dead.append(q)
    for q in dead:
        unsubscribe(user_id, q)

def log_event(event_type: str, description: str, severity: str = "INFO", user_id: Optional[str] = None, ip: Optional[str] = None):
    formalized_text = _formalize_log(description, event_type, severity.upper(), user_id, ip)
    now_utc = datetime.now(timezone.utc)
    entry = Log(
        user_id=user_id, severity=severity.upper(),
        event_type=event_type.upper(), ip_address=ip,
        description=formalized_text, timestamp=now_utc.replace(tzinfo=None)
    )
    try:
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[LOG DB ERROR] {e}")

    ts_iso = now_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    payload = {
        "id": entry.id, "severity": entry.severity, "event_type": entry.event_type,
        "description": formalized_text, "ip": ip or "", "user_id": user_id or "system", "timestamp": ts_iso
    }
    print(f"[{entry.severity}] {entry.event_type} | {formalized_text}")
    if user_id:
        push_to_user(user_id, payload)
    return payload

def get_logs_for_user(user_id: str, limit: int = 100, severity: str = None) -> list:
    q = Log.query.filter_by(user_id=user_id)
    if severity:
        q = q.filter_by(severity=severity.upper())
    return [{
        "id": r.id, "severity": r.severity, "event_type": r.event_type,
        "description": r.description, "ip": r.ip_address or "",
        "timestamp": r.timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
    } for r in q.order_by(Log.timestamp.desc()).limit(limit).all()]