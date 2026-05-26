"""
CatchCatchTV v3 — PostgreSQL Models

pgvector NOTE:
  pgvector requires a separate installer on Windows PostgreSQL.
  The Detection table stores embeddings as JSON array (JSONB) instead,
  which is functionally equivalent for this project's logging purposes.
  On Render (cloud), pgvector is pre-installed and Vector(512) works natively.
"""
import uuid
from datetime import datetime
from app import db


def _uuid():
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = "users"

    id              = db.Column(db.String(36),  primary_key=True, default=_uuid)
    email           = db.Column(db.String(128), unique=True,  nullable=False, index=True)
    username        = db.Column(db.String(64),  unique=True,  nullable=False)
    password_hash   = db.Column(db.String(255), nullable=False)
    role            = db.Column(db.String(32),  default="user")
    is_active       = db.Column(db.Boolean,     default=True)
    failed_attempts = db.Column(db.Integer,     default=0)
    locked_until    = db.Column(db.DateTime,    nullable=True)
    must_reset_password = db.Column(db.Boolean, default=False, nullable=False)
    discord_webhook = db.Column(db.String(512), nullable=True)
    admin_webhook   = db.Column(db.String(512), nullable=True)  # Admin-only: receives ALL alerts
    admin_grace     = db.Column(db.Boolean,     default=False, nullable=False)  # Skip IP block/rate-limit on login
    created_at      = db.Column(db.DateTime,    default=datetime.utcnow)

    cameras    = db.relationship("Camera",      backref="owner", lazy="dynamic", cascade="all, delete-orphan")
    logs       = db.relationship("Log",         backref="owner", lazy="dynamic", cascade="all, delete-orphan")
    sessions   = db.relationship("UserSession", backref="owner", lazy="dynamic", cascade="all, delete-orphan")
    detections = db.relationship("Detection",   backref="owner", lazy="dynamic", cascade="all, delete-orphan")


# ─────────────────────────────────────────────────────────────
# CAMERAS
# ─────────────────────────────────────────────────────────────
class Camera(db.Model):
    __tablename__ = "cameras"

    id         = db.Column(db.String(36),  primary_key=True, default=_uuid)
    user_id    = db.Column(db.String(36),  db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    label      = db.Column(db.String(128), default="My Camera")
    stream_url = db.Column(db.String(512), nullable=True, default="")
    audio_url  = db.Column(db.String(512), nullable=True, default="")  # optional separate audio stream URL
    cam_username = db.Column(db.String(128), nullable=True, default="")   # optional camera login username
    cam_password = db.Column(db.String(256), nullable=True, default="")   # optional camera login password
    ai_enabled = db.Column(db.Boolean,    default=False)
    is_active  = db.Column(db.Boolean,    default=True)
    last_seen  = db.Column(db.DateTime,   nullable=True)
    created_at = db.Column(db.DateTime,   default=datetime.utcnow)


# ─────────────────────────────────────────────────────────────
# SESSIONS
# ─────────────────────────────────────────────────────────────
class UserSession(db.Model):
    __tablename__ = "sessions"

    id            = db.Column(db.String(36),  primary_key=True, default=_uuid)
    user_id       = db.Column(db.String(36),  db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    ip_address    = db.Column(db.String(45),  nullable=True)
    user_agent    = db.Column(db.String(256), nullable=True)
    created_at    = db.Column(db.DateTime,    default=datetime.utcnow)
    last_active   = db.Column(db.DateTime,    default=datetime.utcnow)
    expires_at    = db.Column(db.DateTime,    nullable=False)
    is_revoked    = db.Column(db.Boolean,     default=False)


# ─────────────────────────────────────────────────────────────
# LOGS
# ─────────────────────────────────────────────────────────────
class Log(db.Model):
    __tablename__ = "logs"

    id          = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    user_id     = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    severity    = db.Column(db.String(16), nullable=False, default="INFO")
    # AUTH | SIGNALING | CAMERA | SESSION | SYSTEM | NETWORK
    event_type  = db.Column(db.String(32), nullable=False)
    ip_address  = db.Column(db.String(45), nullable=True)
    description = db.Column(db.Text,       nullable=False, default="")
    timestamp   = db.Column(db.DateTime,   default=datetime.utcnow, index=True)


# ─────────────────────────────────────────────────────────────
# BLOCKED IPs
# ─────────────────────────────────────────────────────────────
class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id            = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    ip_address    = db.Column(db.String(45), unique=True, nullable=False, index=True)
    blocked_until = db.Column(db.DateTime,   nullable=False)
    reason        = db.Column(db.String(256), nullable=True)
    created_by    = db.Column(db.String(36), nullable=True)
    created_at    = db.Column(db.DateTime,   default=datetime.utcnow)


class WhitelistedIP(db.Model):
    __tablename__ = "whitelisted_ips"

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address  = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason      = db.Column(db.String(256), nullable=True)
    created_by  = db.Column(db.String(36), nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)


class SecuritySetting(db.Model):
    __tablename__ = "security_settings"

    key        = db.Column(db.String(64), primary_key=True)
    value      = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IncidentNote(db.Model):
    __tablename__ = "incident_notes"

    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    admin_id   = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    note       = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class AdminAction(db.Model):
    __tablename__ = "admin_actions"

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    admin_id    = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action      = db.Column(db.String(64), nullable=False)
    target_type = db.Column(db.String(32), nullable=False)
    target_id   = db.Column(db.String(128), nullable=True)
    details     = db.Column(db.JSON, nullable=True)
    ip_address  = db.Column(db.String(45), nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# ─────────────────────────────────────────────────────────────
# SIGNALING  (WebRTC offer/answer/ICE via HTTP polling)
# ─────────────────────────────────────────────────────────────
class SignalingMessage(db.Model):
    __tablename__ = "signaling"

    id         = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    room_id    = db.Column(db.String(36), nullable=False, index=True)
    sender     = db.Column(db.String(16), nullable=False)
    msg_type   = db.Column(db.String(16), nullable=False)
    payload    = db.Column(db.Text,       nullable=False)
    created_at = db.Column(db.DateTime,   default=datetime.utcnow)
    consumed   = db.Column(db.Boolean,    default=False)


# ─────────────────────────────────────────────────────────────
# DETECTIONS  (AI events + vector embedding stored as JSONB)
#
# pgvector stores embeddings as VECTOR(512) natively.
# On Windows local PostgreSQL without pgvector installed,
# we store the same 512-float embedding as a JSONB array.
# The data is identical — only the column type differs.
# On Render (cloud PostgreSQL), pgvector is available and
# the column can be migrated to VECTOR(512) for similarity search.
# ─────────────────────────────────────────────────────────────
class Detection(db.Model):
    __tablename__ = "detections"

    id             = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    user_id        = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    detected_class = db.Column(db.String(64), nullable=False)
    confidence     = db.Column(db.Float,      nullable=False)
    bounding_box   = db.Column(db.JSON,       nullable=True)
    is_alert       = db.Column(db.Boolean,    default=False)
    # Frame embedding stored as JSONB array of 512 floats
    # (functionally equivalent to pgvector VECTOR(512))
    frame_embedding = db.Column(db.JSON,      nullable=True)
    alert_sent     = db.Column(db.Boolean,    default=False)
    timestamp      = db.Column(db.DateTime,   default=datetime.utcnow, index=True)

class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.String(64), nullable=False)
    token_hash = db.Column(db.String(128), nullable=False, unique=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used       = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ─────────────────────────────────────────────────────────────
# RATE LIMIT HITS  (replaces the old in-memory dict)
#
# Storing rate limit hits in the DB means limits survive
# Railway restarts and work correctly across multiple workers.
# Old rows are cleaned up automatically by is_rate_limited().
# ─────────────────────────────────────────────────────────────
class RateLimit(db.Model):
    __tablename__ = "rate_limits"

    id         = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    timestamp  = db.Column(db.DateTime,   default=datetime.utcnow, nullable=False, index=True)
