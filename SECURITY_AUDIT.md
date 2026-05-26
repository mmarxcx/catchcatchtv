# CatchCatchTV Security Audit Notes

Date: 2026-05-21

## Findings fixed in this pass

1. Dependency vulnerabilities in `requirements.txt`
   - `pip-audit` reported vulnerable/unused `flask-cors==6.0.2` and `pyjwt==2.12.1`, plus vulnerable `python-dotenv==1.0.1`.
   - Removed unused `flask-cors` and `pyjwt`.
   - Upgraded `python-dotenv` to `1.2.2`.
   - Verification: `python -m pip_audit -r requirements.txt` now reports no known vulnerabilities.

2. Admin panel could observe threats but not respond directly
   - Added manual IP block, temporary/permanent block durations, unblock, whitelist, active threat summary, threat timeline, CSV export, incident notes, AbuseIPDB lookup, and reverse DNS lookup.
   - Added kill session, lock/unlock account, and force password reset controls.
   - New routes are all protected by `@admin_required` and existing Flask-WTF CSRF enforcement.
   - Admin buttons use delegated event listeners instead of inline `onclick`, so they work under the app's CSP.

3. Auto-blocking was hardcoded
   - Replaced fixed failed-login block behavior with configurable settings stored in `security_settings`.
   - Added configurable threshold, time window, block duration, live refresh interval, and honeypot auto-block.

4. No emergency access controls
   - Added maintenance mode and emergency lockdown mode.
   - Lockdown allows only whitelisted IPs, so whitelist your admin IP before enabling it.

5. No honeypot scanner detection
   - Added request-time detection for common scanner paths such as `/.env`, `/wp-admin`, `/phpmyadmin`, `/admin-backup`, `/server-status`, `/debug`, and `/actuator`.
   - Hits are logged as critical and can auto-block.

6. Forced password reset was not enforceable
   - Added `users.must_reset_password`.
   - Admins can flag users.
   - Flagged users are redirected to settings and blocked from normal API access until changing their password.

## Existing controls confirmed

- Production `SECRET_KEY` is required in `app/__init__.py`; missing production secret raises at startup.
- Session cookies use `HttpOnly`, `SameSite=Lax`, and `Secure` in production.
- Admin routes use `admin_required`.
- User camera updates and camera proxy lookups are scoped by `user_id`.
- WebRTC signaling room access checks block cross-user room access.
- Jinja log rendering in the dashboard uses text nodes rather than raw HTML for log descriptions.
- No file upload surface was found in the uploaded codebase.

## Remaining risks / follow-up

- `db_setup.sql` and `.env.example` contain local demo database credentials. They are not production secrets, but public repos should clearly mark them as local-only.
- `main.py` uses `debug = FLASK_ENV != "production"`. Railway must set `FLASK_ENV=production`.
- AbuseIPDB lookup requires `ABUSEIPDB_API_KEY`.
- Geo-blocking, 2FA enrollment/enforcement, PDF reports, daily digest scheduling, Discord/Telegram escalation timers, and full request-body replay are not fully implemented in this pass.
- There is no Alembic/Flask-Migrate setup. Additive schema upgrades are handled by `db.create_all()` plus small startup `ALTER TABLE` statements, but a real migration system is recommended before more production schema changes.

## Manual test checklist

1. Log in as admin and open `/admin`.
2. Confirm the new Security tab loads settings, active threats, and whitelisted IPs.
3. Trigger a failed login threshold and confirm the source IP is blocked unless whitelisted.
4. Use Block IP on a warning/alert/critical log row and confirm the IP appears in Blocked IPs.
5. Whitelist your own admin IP before testing Emergency Lockdown.
6. Kill a non-admin user's session and confirm their next API/page request is rejected.
7. Lock a non-admin user and confirm login fails.
8. Force password reset for a user and confirm they must change password before normal access.
9. Hit `/.env` or `/wp-admin` from a test IP and confirm critical logging and optional auto-block.
10. Run `python -m compileall app main.py`.
11. Run `python -m pip_audit -r requirements.txt`.
