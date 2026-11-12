"""All security controls live here so they are easy to explain, audit and test.

Sections
  1. IAM          roles and permissions (RBAC, least privilege)
  2. Secrets      loaded from environment or a private file, never hard-coded
  3. Passwords    strong-password policy + PBKDF2 hashing
  4. MFA          TOTP (RFC 6238) with replay protection
  5. Encryption   field-level encryption of sensitive data before it reaches the database
  6. Audit        tamper-evident (hash-chained) security log
  7. Rate limits  per-IP sliding window (brute force / flooding / DDoS at app layer)
  8. CSRF         per-session token on every state-changing form
  9. Sessions     server-side sessions with idle + absolute timeout and revocation
 10. Decorators   login / permission / JWT guards
 11. Headers      CSP, HSTS, clickjacking and MIME-sniffing protection
 12. JWT          short-lived signed API tokens with revocation
 13. Webhooks     HMAC-SHA256 signature + timestamp (anti-replay)
 14. Perimeter    host allow-list, HTTPS enforcement
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import struct
import threading
import time
import urllib.parse
from collections import deque
from functools import wraps
from pathlib import Path

import jwt
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from flask import abort, current_app, g, has_request_context, jsonify, redirect, request, session, url_for
from werkzeug.exceptions import TooManyRequests
from werkzeug.security import check_password_hash, generate_password_hash

from . import db

log = logging.getLogger("portal.security")

# ---------------------------------------------------------------------------
# 1. IAM: roles and permissions
# ---------------------------------------------------------------------------
PERMISSIONS = {
    "student": frozenset({"results:read_own", "fees:read_own", "fees:pay"}),
    "lecturer": frozenset({"results:read_any", "grades:propose"}),
    "registry": frozenset({"results:read_any", "grades:approve"}),
    "admin": frozenset({"audit:read"}),   # admins cannot read or change grades (separation of duties)
}


def permissions_for(role: str):
    return PERMISSIONS.get(role, frozenset())


def can(permission: str) -> bool:
    user = g.get("user")
    return user is not None and permission in permissions_for(user["role"])


# ---------------------------------------------------------------------------
# 2. Secrets
# ---------------------------------------------------------------------------
_SECRET_ENV = {
    "SECRET_KEY": "PORTAL_SECRET_KEY",
    "JWT_SECRET": "PORTAL_JWT_SECRET",
    "FERNET_KEY": "PORTAL_FERNET_KEY",
    "WEBHOOK_SECRET": "PORTAL_WEBHOOK_SECRET",
}


def load_secrets(instance_path) -> dict:
    """Environment variables win. Otherwise generate once and keep in instance/secrets.json (chmod 600)."""
    path = Path(instance_path) / "secrets.json"
    stored = json.loads(path.read_text()) if path.exists() else {}
    changed = False
    out = {}
    for key, env_name in _SECRET_ENV.items():
        value = os.environ.get(env_name) or stored.get(key)
        if not value:
            value = Fernet.generate_key().decode() if key == "FERNET_KEY" else secrets.token_urlsafe(48)
            stored[key] = value
            changed = True
        out[key] = value
    if changed:
        path.write_text(json.dumps(stored))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return out


# ---------------------------------------------------------------------------
# 3. Passwords
# ---------------------------------------------------------------------------
BANNED_WORDS = ("password", "qwerty", "letmein", "welcome", "admin", "iloveyou",
                "changeme", "123456", "abc123", "student", "portal")


def validate_password(password: str, username: str = "", email: str = "") -> list:
    cfg = current_app.config
    errors = []
    if len(password) < cfg["PASSWORD_MIN_LENGTH"]:
        errors.append("Password must be at least %d characters long." % cfg["PASSWORD_MIN_LENGTH"])
    if len(password) > 128:
        errors.append("Password must be at most 128 characters long.")
    if not re.search(r"[a-z]", password):
        errors.append("Password needs a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password needs an uppercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password needs a digit.")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password needs a symbol (for example ! # % -).")
    lowered = password.lower()
    if username and len(username) >= 3 and username.lower() in lowered:
        errors.append("Password must not contain your username.")
    local = email.split("@")[0].lower() if email else ""
    if len(local) >= 4 and local in lowered:
        errors.append("Password must not contain your email name.")
    if any(word in lowered for word in BANNED_WORDS):
        errors.append("Password contains a very common word or pattern.")
    if re.search(r"(.)\1{3,}", password):
        errors.append("Password must not repeat a character four or more times in a row.")
    return errors


def hash_password(password: str) -> str:
    iterations = current_app.config["PBKDF2_ITERATIONS"]
    return generate_password_hash(password, method="pbkdf2:sha256:%d" % iterations, salt_length=16)


def verify_password(stored_hash: str, password: str) -> bool:
    return check_password_hash(stored_hash, password)


def fake_verify(password: str) -> None:
    """Spend the same time as a real check so attackers cannot tell if a username exists."""
    dummy = current_app.extensions.get("dummy_hash")
    if dummy is None:
        dummy = hash_password(secrets.token_urlsafe(16))
        current_app.extensions["dummy_hash"] = dummy
    check_password_hash(dummy, password)


# ---------------------------------------------------------------------------
# 4. MFA: TOTP (RFC 6238), implemented with the standard library
# ---------------------------------------------------------------------------
def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode()


def _hotp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(number).zfill(digits)


def totp_now(secret: str, at=None, step: int = 30) -> str:
    moment = time.time() if at is None else at
    return _hotp(secret, int(moment // step))


def verify_totp(secret: str, code: str, last_step: int = 0, window: int = 1, now=None):
    """Return the matched time-step, or None. A step can only be used once (replay protection)."""
    code = (code or "").strip().replace(" ", "")
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    current = int((time.time() if now is None else now) // 30)
    matched = None
    for step in range(current - window, current + window + 1):
        if step > last_step and hmac.compare_digest(_hotp(secret, step), code):
            matched = step
    return matched


def otpauth_uri(secret: str, username: str, issuer: str = "Secure Student Portal") -> str:
    label = urllib.parse.quote("%s:%s" % (issuer, username))
    return "otpauth://totp/%s?secret=%s&issuer=%s&digits=6&period=30" % (
        label, secret, urllib.parse.quote(issuer))


# ---------------------------------------------------------------------------
# 5. Encryption of sensitive fields (Fernet = AES-128-CBC + HMAC-SHA256)
# ---------------------------------------------------------------------------
def _fernet() -> MultiFernet:
    keys = [k.strip() for k in current_app.config["FERNET_KEY"].split(",") if k.strip()]
    return MultiFernet([Fernet(k.encode()) for k in keys])   # first key encrypts, any key decrypts


def encrypt_field(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_field(token):
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None


# ---------------------------------------------------------------------------
# 6. Audit log: every row contains the hash of the previous row
# ---------------------------------------------------------------------------
GENESIS = "0" * 64


def client_ip() -> str:
    return (request.remote_addr or "?") if has_request_context() else "-"


def _row_hash(prev_hash, ts, event, user_id, ip, detail) -> str:
    text = "|".join([prev_hash, str(ts), event, str(user_id), str(ip), detail])
    return hashlib.sha256(text.encode()).hexdigest()


def audit(event: str, user_id=None, detail: str = "") -> None:
    if user_id is None and has_request_context() and g.get("user") is not None:
        user_id = g.user["id"]
    detail = re.sub(r"[\r\n\t]", " ", str(detail))[:300]       # prevents log forging
    ip = client_ip()
    ts = int(time.time())
    with db.transaction() as conn:
        prev = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = prev["hash"] if prev else GENESIS
        digest = _row_hash(prev_hash, ts, event, user_id, ip, detail)
        conn.execute(
            "INSERT INTO audit_log (ts, event, user_id, ip, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
            (ts, event, user_id, ip, detail, prev_hash, digest))
    log.info("event=%s user=%s ip=%s detail=%s", event, user_id, ip, detail)


def verify_audit_chain():
    """Return (ok, first_bad_row_id, rows_checked)."""
    prev_hash = GENESIS
    count = 0
    for row in db.query_all("SELECT * FROM audit_log ORDER BY id ASC"):
        expected = _row_hash(prev_hash, row["ts"], row["event"], row["user_id"], row["ip"], row["detail"] or "")
        if row["prev_hash"] != prev_hash or row["hash"] != expected:
            return False, row["id"], count
        prev_hash = row["hash"]
        count += 1
    return True, None, count


# ---------------------------------------------------------------------------
# 7. Rate limiting (sliding window, per client IP)
# ---------------------------------------------------------------------------
class RateLimiter:
    """In-memory limiter. For several server processes use Redis or the Nginx limit_req layer as well."""

    def __init__(self):
        self._hits = {}
        self._announced = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: int):
        """Return (allowed, retry_after_seconds, first_block_in_window)."""
        now = time.monotonic()
        with self._lock:
            queue = self._hits.setdefault(key, deque())
            while queue and queue[0] <= now - window:
                queue.popleft()
            if len(queue) >= limit:
                retry = int(window - (now - queue[0])) + 1
                first = now - self._announced.get(key, -1e9) > window
                if first:
                    self._announced[key] = now
                return False, retry, first
            queue.append(now)
            if len(self._hits) > 20000:
                self._hits = {k: v for k, v in self._hits.items() if v}
            return True, 0, False


def _limiter() -> RateLimiter:
    return current_app.extensions["limiter"]


def rate_limit(name: str, config_key: str, methods=("POST",)):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if request.method in methods:
                limit, window = current_app.config[config_key]
                allowed, retry, first = _limiter().hit("%s:%s" % (name, client_ip()), limit, window)
                if not allowed:
                    if first:
                        audit("rate_limited", detail=name)
                    raise TooManyRequests(retry_after=retry)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def global_rate_limit():
    limit, window = current_app.config["GLOBAL_RATE"]
    allowed, retry, first = _limiter().hit("global:%s" % client_ip(), limit, window)
    if not allowed:
        if first:
            audit("rate_limited", detail="global")
        raise TooManyRequests(retry_after=retry)


# ---------------------------------------------------------------------------
# 8. CSRF
# ---------------------------------------------------------------------------
def csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def csrf_exempt(view):
    """Only for endpoints authenticated by something other than cookies (JWT / HMAC signature)."""
    view._csrf_exempt = True
    return view


def csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    view = current_app.view_functions.get(request.endpoint)
    if view is not None and getattr(view, "_csrf_exempt", False):
        return None
    expected = session.get("_csrf", "")
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    if not expected or not hmac.compare_digest(expected, supplied):
        audit("csrf_failed", detail=request.path)
        abort(400)
    return None


# ---------------------------------------------------------------------------
# 9. Server-side sessions
# ---------------------------------------------------------------------------
def _sid_hash(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()    # the database never stores the raw session id


def start_session(user_id: int) -> None:
    session.clear()                                    # new session id on login (anti session-fixation)
    sid = secrets.token_urlsafe(32)
    now = int(time.time())
    db.execute("INSERT INTO auth_sessions (sid_hash, user_id, created_at, last_seen, ip) VALUES (?,?,?,?,?)",
               (_sid_hash(sid), user_id, now, now, client_ip()))
    session["sid"] = sid
    session["_csrf"] = secrets.token_urlsafe(32)
    session.permanent = True


def revoke_current_session() -> None:
    sid = session.get("sid")
    if sid:
        db.execute("UPDATE auth_sessions SET revoked = 1 WHERE sid_hash = ?", (_sid_hash(sid),))


def revoke_other_sessions(user_id: int) -> None:
    sid = session.get("sid", "")
    db.execute("UPDATE auth_sessions SET revoked = 1 WHERE user_id = ? AND sid_hash <> ?",
               (user_id, _sid_hash(sid)))


def load_user() -> None:
    g.user = None
    sid = session.get("sid")
    if not sid:
        return
    cfg = current_app.config
    now = int(time.time())
    row = db.query_one("SELECT * FROM auth_sessions WHERE sid_hash = ?", (_sid_hash(sid),))
    if (row is None or row["revoked"]
            or now - row["last_seen"] > cfg["SESSION_IDLE_SECONDS"]
            or now - row["created_at"] > cfg["SESSION_ABSOLUTE_SECONDS"]):
        if row is not None and not row["revoked"]:
            db.execute("UPDATE auth_sessions SET revoked = 1 WHERE sid_hash = ?", (row["sid_hash"],))
        session.clear()
        return
    user = db.query_one("SELECT * FROM users WHERE id = ? AND active = 1", (row["user_id"],))
    if user is None:
        session.clear()
        return
    db.execute("UPDATE auth_sessions SET last_seen = ? WHERE sid_hash = ?", (now, row["sid_hash"]))
    g.user = user


# ---------------------------------------------------------------------------
# 10. Decorators
# ---------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get("user") is None:
            return redirect(url_for("auth.login"))       # no ?next= parameter, so no open redirect
        return view(*args, **kwargs)
    return wrapper


def permission_required(permission: str):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.get("user") is None:
                return redirect(url_for("auth.login"))
            if permission not in permissions_for(g.user["role"]):
                audit("permission_denied", detail="%s %s" % (permission, request.path))
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def jwt_required(permission=None):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return _unauthorized("missing_token")
            try:
                claims = decode_token(header[7:].strip())
                user = db.query_one("SELECT * FROM users WHERE id = ? AND active = 1", (int(claims["sub"]),))
            except (jwt.InvalidTokenError, ValueError) as exc:
                audit("jwt_rejected", detail=type(exc).__name__)
                return _unauthorized("invalid_token")
            if user is None:
                return _unauthorized("invalid_token")
            # The role comes from the database, never from the token, so a stale or forged claim is useless.
            if permission and permission not in permissions_for(user["role"]):
                audit("permission_denied", user_id=user["id"], detail="%s %s" % (permission, request.path))
                return jsonify(error="forbidden"), 403
            g.api_user = user
            g.jwt_claims = claims
            return view(*args, **kwargs)
        return wrapper
    return decorator


def _unauthorized(reason: str):
    return jsonify(error=reason), 401, {"WWW-Authenticate": "Bearer"}


# ---------------------------------------------------------------------------
# 11. Security headers
# ---------------------------------------------------------------------------
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")


def add_security_headers(response):
    h = response.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["Server"] = "StudentPortal"                          # hides framework and version
    if request.is_secure or current_app.config["FORCE_HTTPS"]:
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint != "static":
        h["Cache-Control"] = "no-store"
        h["Pragma"] = "no-cache"
    return response


# ---------------------------------------------------------------------------
# 12. JWT
# ---------------------------------------------------------------------------
def issue_token(user):
    cfg = current_app.config
    now = int(time.time())
    jti = secrets.token_urlsafe(16)
    claims = {
        "iss": cfg["JWT_ISSUER"], "aud": cfg["JWT_AUDIENCE"], "sub": str(user["id"]),
        "role": user["role"], "iat": now, "nbf": now, "exp": now + cfg["JWT_TTL_SECONDS"], "jti": jti,
    }
    return jwt.encode(claims, cfg["JWT_SECRET"], algorithm="HS256"), jti, claims["exp"]


def decode_token(token: str) -> dict:
    cfg = current_app.config
    claims = jwt.decode(
        token, cfg["JWT_SECRET"],
        algorithms=["HS256"],                              # pinned: "alg: none" and key-confusion are rejected
        audience=cfg["JWT_AUDIENCE"], issuer=cfg["JWT_ISSUER"],
        options={"require": ["exp", "iat", "nbf", "sub", "jti", "aud", "iss"]},
    )
    if db.query_one("SELECT 1 FROM revoked_tokens WHERE jti = ?", (claims["jti"],)):
        raise jwt.InvalidTokenError("revoked")
    return claims


# ---------------------------------------------------------------------------
# 13. Webhooks: X-Signature: t=<unix time>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">
# ---------------------------------------------------------------------------
def sign_webhook(raw: bytes, secret: str, timestamp=None) -> str:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    mac = hmac.new(secret.encode(), str(ts).encode() + b"." + raw, hashlib.sha256).hexdigest()
    return "t=%d,v1=%s" % (ts, mac)


def verify_webhook(raw: bytes, header: str):
    try:
        parts = dict(item.split("=", 1) for item in header.split(",") if "=" in item)
        ts = int(parts.get("t", ""))
    except ValueError:
        return False, "malformed_header"
    signature = parts.get("v1", "")
    if abs(time.time() - ts) > current_app.config["WEBHOOK_TOLERANCE_SECONDS"]:
        return False, "stale_timestamp"                  # blocks replay of old captured requests
    expected = sign_webhook(raw, current_app.config["WEBHOOK_SECRET"], ts).split("v1=", 1)[1]
    if not hmac.compare_digest(expected, signature):    # constant-time comparison
        return False, "bad_signature"
    return True, "ok"


# ---------------------------------------------------------------------------
# 14. Perimeter checks and wiring
# ---------------------------------------------------------------------------
def enforce_perimeter():
    host = request.host.split(":")[0].lower()
    if host not in current_app.config["ALLOWED_HOSTS"]:
        audit("bad_host_header", detail=re.sub(r"[^\w.:-]", "?", host)[:60])
        abort(400)
    if current_app.config["FORCE_HTTPS"] and not request.is_secure:
        return redirect(request.url.replace("http://", "https://", 1), code=301)
    return None


def init_app(app) -> None:
    app.before_request(enforce_perimeter)
    app.before_request(global_rate_limit)
    app.before_request(load_user)
    app.before_request(csrf_protect)
    app.after_request(add_security_headers)

    @app.context_processor
    def _inject():
        return {"user": g.get("user"), "csrf_token": csrf_token, "can": can}
