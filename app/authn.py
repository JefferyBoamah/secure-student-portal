"""Credential and second-factor checks shared by the web login and the API token endpoint."""
from __future__ import annotations

import re
import time

from flask import current_app

from . import db, security


def _clean(text: str) -> str:
    return re.sub(r"[^\w.@-]", "?", text)[:40]


def register_failure(user) -> None:
    """Count a failed password or MFA attempt and lock the account after too many."""
    cfg = current_app.config
    db.execute("UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ?", (user["id"],))
    row = db.query_one("SELECT failed_logins FROM users WHERE id = ?", (user["id"],))
    if row["failed_logins"] >= cfg["LOGIN_MAX_FAILURES"]:
        db.execute("UPDATE users SET locked_until = ?, failed_logins = 0 WHERE id = ?",
                   (int(time.time()) + cfg["LOCKOUT_SECONDS"], user["id"]))
        security.audit("account_locked", user_id=user["id"], detail="too many failed attempts")


def check_credentials(username: str, password: str):
    """Return the user row, or None. The caller must not reveal which part was wrong."""
    user = db.query_one("SELECT * FROM users WHERE username = ? AND active = 1", (username,))
    if user is None:
        security.fake_verify(password)
        security.audit("login_failed", detail="unknown user %s" % _clean(username))
        return None
    if user["locked_until"] > int(time.time()):
        security.fake_verify(password)
        security.audit("login_blocked", user_id=user["id"], detail="account locked")
        return None
    if not security.verify_password(user["password_hash"], password):
        register_failure(user)
        security.audit("login_failed", user_id=user["id"], detail="wrong password")
        return None
    return user


def verify_second_factor(user, code: str) -> bool:
    fresh = db.query_one("SELECT * FROM users WHERE id = ?", (user["id"],))
    if fresh is None or fresh["locked_until"] > int(time.time()):
        return False
    secret = security.decrypt_field(fresh["totp_secret_enc"])
    step = security.verify_totp(secret, code, fresh["last_totp_step"]) if secret else None
    if step is None:
        register_failure(fresh)
        security.audit("mfa_failed", user_id=fresh["id"])
        return False
    db.execute("UPDATE users SET last_totp_step = ?, failed_logins = 0 WHERE id = ?", (step, fresh["id"]))
    return True


def pending_user():
    """The user who passed the password step but has not finished MFA (short-lived)."""
    from flask import session
    pre = session.get("pre_mfa")
    if not pre or int(time.time()) - int(pre.get("ts", 0)) > current_app.config["PRE_MFA_SECONDS"]:
        session.pop("pre_mfa", None)
        return None
    return db.query_one("SELECT * FROM users WHERE id = ? AND active = 1", (pre["uid"],))
