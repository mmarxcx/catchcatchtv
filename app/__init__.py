import os
import secrets as _secrets
from flask import Flask, g, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from werkzeug.middleware.proxy_fix import ProxyFix

db     = SQLAlchemy()
bcrypt = Bcrypt()
csrf   = CSRFProtect()
mail   = Mail()


def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")

    # Fix for Railway Load Balancers — reads real user IP instead of proxy IP
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    is_prod = os.environ.get("FLASK_ENV") == "production"

    # ── SECRET KEY — crash loudly if missing in production ──
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        if is_prod:
            raise RuntimeError(
                "SECRET_KEY environment variable is not set! "
                "Go to Railway > your service > Variables and add it. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        else:
            secret = "secret123"
    app.config["SECRET_KEY"] = secret

    # Fix Render/Railway postgres:// to postgresql://
    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://username:password@localhost:5432/catchcatchtv_db"
    )
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"]        = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"]      = {
        "pool_pre_ping": True,
        "pool_recycle":  300,
        "pool_timeout":  20,
    }

    app.config["SESSION_COOKIE_HTTPONLY"]  = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"]   = is_prod
    app.config["WTF_CSRF_TIME_LIMIT"]     = None

    app.config["SESSION_INACTIVITY_SECONDS"] = int(os.environ.get("SESSION_INACTIVITY", "1800"))
    app.config["MAX_ACTIVE_STREAMS"]         = int(os.environ.get("MAX_ACTIVE_STREAMS", "2"))
    app.config["MAX_FAILED_ATTEMPTS"]        = 5

    app.config["STUN_SERVERS"] = [
        {"urls": "stun:stun.l.google.com:19302"},
        {"urls": "stun:stun1.l.google.com:19302"},
        {"urls": "stun:stun.cloudflare.com:3478"},
    ]

    app.config["MAIL_SERVER"]         = os.environ.get("MAIL_SERVER",   "smtp.gmail.com")
    app.config["MAIL_PORT"]           = int(os.environ.get("MAIL_PORT", "587"))
    app.config["MAIL_USE_TLS"]        = os.environ.get("MAIL_USE_TLS",  "true").lower() == "true"
    app.config["MAIL_USERNAME"]       = os.environ.get("MAIL_USERNAME",  "")
    app.config["MAIL_PASSWORD"]       = os.environ.get("MAIL_PASSWORD",  "")
    app.config["MAIL_DEFAULT_SENDER"] = os.environ.get(
        "MAIL_DEFAULT_SENDER",
        app.config["MAIL_USERNAME"] or "noreply@catchcatchtv.app"
    )

    db.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)

    @app.before_request
    def enforce_security_controls():
        g.csp_nonce = _secrets.token_urlsafe(16)
        if request.endpoint in ("static", "main.healthz"):
            return None
        from app.security import is_ip_blocked, is_ip_whitelisted, get_security_setting, block_ip
        from app.logger import log_event
        ip = request.remote_addr or ""
        honeypots = {
            "/wp-admin", "/phpmyadmin", "/admin-backup", "/backup", "/.env",
            "/config.php", "/server-status", "/debug", "/actuator", "/vendor/phpunit",
        }
        path = request.path.rstrip("/") or "/"
        if path in honeypots or any(path.startswith(p + "/") for p in honeypots):
            log_event("SECURITY", f"Honeypot scan path requested: {request.path}", "CRITICAL", None, ip)
            if get_security_setting("honeypot_auto_block", True) and not is_ip_whitelisted(ip):
                block_ip(ip, get_security_setting("auto_block_minutes", 60), "Honeypot endpoint scan")
            return jsonify({"error": "Not found"}), 404
        if is_ip_blocked(ip):
            return jsonify({"error": "Your IP is blocked."}), 403
        if get_security_setting("lockdown_mode", False) and not is_ip_whitelisted(ip):
            return jsonify({"error": "Emergency lockdown is active."}), 403
        if get_security_setting("maintenance_mode", False):
            token = request.cookies.get("cctv_session")
            allowed = False
            if token:
                from app.security import validate_session
                from app.models import User
                sess = validate_session(token, ip)
                user = db.session.get(User, sess.user_id) if sess else None
                allowed = bool(user and user.role == "admin")
            if not allowed and not request.path.startswith("/api/"):
                return "<h1>Maintenance Mode</h1><p>CatchCatchTV is temporarily unavailable.</p>", 503
            if not allowed:
                return jsonify({"error": "Maintenance mode is active."}), 503
        return None

    @app.after_request
    def add_security_headers(response):
        nonce = getattr(g, "csp_nonce", "")

        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=(self)"

        if is_prod:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # nonce replaces unsafe-inline for scripts.
        # unsafe-eval is kept only for the ONNX/AI worker scripts.
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval' https://cdn.jsdelivr.net; "
            f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            f"font-src 'self' https://fonts.gstatic.com; "
            f"img-src 'self' data: blob: http: https:; "
            f"media-src 'self' blob: http: https:; "
            f"connect-src 'self' wss: ws: http: https: https://cdn.jsdelivr.net https://storage.googleapis.com blob:; "
            f"worker-src 'self' blob: https://cdn.jsdelivr.net https://storage.googleapis.com; "
            f"frame-ancestors 'none';"
        )

        # CSRF token cookie — HttpOnly=False so JS can read it to send in headers
        from flask_wtf.csrf import generate_csrf
        response.set_cookie(
            "csrf_token",
            generate_csrf(),
            samesite="Lax",
            secure=is_prod,
            httponly=False,
        )

        return response

    with app.app_context():
        try:
            db.session.execute(db.text("CREATE EXTENSION IF NOT EXISTS vector;"))
            db.session.commit()
            print("[DB] pgvector extension enabled.")
        except Exception:
            db.session.rollback()
            print("[DB] pgvector not available — using JSONB for embeddings.")

        from app.routes import bp
        app.register_blueprint(bp)
        db.create_all()
        _ensure_schema()
        print("[DB] All tables ready.")

        _promote_admin(os.environ.get("ADMIN_EMAIL", ""))
    return app


def _promote_admin(email: str):
    if not email:
        return
    try:
        from app.models import User
        user = User.query.filter_by(email=email).first()
        if user and user.role != "admin":
            user.role = "admin"
            db.session.commit()
            print(f"[ADMIN] Promoted {email} to admin.")
        elif user:
            print(f"[ADMIN] {email} is already admin.")
        else:
            print(f"[ADMIN] Admin email '{email}' not registered yet.")
    except Exception as e:
        db.session.rollback()
        print(f"[ADMIN] Promote failed: {e}")


def _ensure_schema():
    """
    db.create_all() creates new tables but does not add columns to existing Railway
    tables. These additive migrations keep upgrades non-destructive.
    """
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    existing = {
        table: {col["name"] for col in inspector.get_columns(table)}
        for table in inspector.get_table_names()
    }
    additions = [
        ("users",    "must_reset_password", "BOOLEAN NOT NULL DEFAULT FALSE"),
        ("blocked_ips", "created_by",       "VARCHAR(36)"),
        ("cameras",  "audio_url",           "VARCHAR(512) DEFAULT ''"),
    ]
    for table, column, definition in additions:
        if column in existing.get(table, set()):
            continue
        stmt = f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        try:
            db.session.execute(db.text(stmt))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            print(f"[DB] Schema upgrade skipped: {exc}")
