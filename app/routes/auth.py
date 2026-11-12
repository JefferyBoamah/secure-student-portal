"""Registration, login (password + TOTP), logout and password change."""
from __future__ import annotations

import re
import sqlite3
import time

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for

from .. import authn, db, security

bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.[A-Za-z]{2,}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{1,78}$")
PHONE_RE = re.compile(r"^\+?[0-9]{9,15}$")


@bp.route("/register", methods=["GET", "POST"])
@security.rate_limit("register", "REGISTER_RATE")
def register():
    if request.method == "GET":
        return render_template("register.html", form={})
    form = {k: request.form.get(k, "").strip() for k in ("username", "email", "full_name", "phone")}
    password = request.form.get("password", "")
    errors = []
    if not USERNAME_RE.match(form["username"]):
        errors.append("Username must be 3 to 30 letters, digits or underscores.")
    if not EMAIL_RE.match(form["email"]):
        errors.append("Enter a valid email address.")
    if not NAME_RE.match(form["full_name"]):
        errors.append("Enter your full name (letters, spaces, . ' - only).")
    if form["phone"] and not PHONE_RE.match(form["phone"]):
        errors.append("Phone must be 9 to 15 digits, optionally starting with +.")
    if password != request.form.get("password2", ""):
        errors.append("Passwords do not match.")
    errors += security.validate_password(password, form["username"], form["email"])
    if errors:
        return render_template("register.html", form=form, errors=errors), 400
    try:
        cur = db.execute(
            "INSERT INTO users (username, email, full_name, password_hash, role, phone_enc, totp_secret_enc, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (form["username"], form["email"], form["full_name"], security.hash_password(password),
             "student",                                   # role is never taken from the request (no mass assignment)
             security.encrypt_field(form["phone"]) if form["phone"] else None,
             security.encrypt_field(security.new_totp_secret()), int(time.time())))
    except sqlite3.IntegrityError:
        security.audit("register_conflict", detail=form["username"][:30])
        return render_template("register.html", form=form,
                               errors=["That username or email is already registered."]), 409
    security.audit("register", user_id=cur.lastrowid)
    session.clear()
    session["pre_mfa"] = {"uid": cur.lastrowid, "ts": int(time.time())}
    return redirect(url_for("auth.mfa_setup"))


@bp.route("/login", methods=["GET", "POST"])
@security.rate_limit("login", "LOGIN_RATE")
def login():
    if g.user is not None:
        return redirect(url_for("portal.dashboard"))
    if request.method == "GET":
        return render_template("login.html")
    user = authn.check_credentials(request.form.get("username", "").strip(), request.form.get("password", ""))
    if user is None:
        # One generic message for unknown user, wrong password and locked account.
        return render_template("login.html", error="Invalid username or password."), 401
    session.clear()
    session["pre_mfa"] = {"uid": user["id"], "ts": int(time.time())}
    return redirect(url_for("auth.mfa_verify" if user["mfa_enabled"] else "auth.mfa_setup"))


@bp.route("/mfa/setup", methods=["GET", "POST"])
@security.rate_limit("mfa", "MFA_RATE")
def mfa_setup():
    user = authn.pending_user()
    if user is None:
        return redirect(url_for("auth.login"))
    if user["mfa_enabled"]:
        return redirect(url_for("auth.mfa_verify"))
    secret = security.decrypt_field(user["totp_secret_enc"])
    if request.method == "POST":
        if authn.verify_second_factor(user, request.form.get("code", "")):
            db.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", (user["id"],))
            security.audit("mfa_enrolled", user_id=user["id"])
            return _finish_login(user)
        flash("That code is not valid. Check the time on your phone and try again.", "error")
    return render_template("mfa_setup.html", secret=secret,
                           uri=security.otpauth_uri(secret, user["username"]))


@bp.route("/mfa/verify", methods=["GET", "POST"])
@security.rate_limit("mfa", "MFA_RATE")
def mfa_verify():
    user = authn.pending_user()
    if user is None:
        return redirect(url_for("auth.login"))
    if not user["mfa_enabled"]:
        return redirect(url_for("auth.mfa_setup"))
    if request.method == "POST":
        if authn.verify_second_factor(user, request.form.get("code", "")):
            return _finish_login(user)
        flash("Invalid or expired code.", "error")
        if db.query_one("SELECT locked_until FROM users WHERE id = ?", (user["id"],))["locked_until"] > time.time():
            session.pop("pre_mfa", None)
            return redirect(url_for("auth.login"))
    return render_template("mfa_verify.html")


def _finish_login(user):
    session.pop("pre_mfa", None)
    db.execute("UPDATE users SET failed_logins = 0, last_login_at = ?, last_login_ip = ? WHERE id = ?",
               (int(time.time()), security.client_ip(), user["id"]))
    security.start_session(user["id"])
    security.audit("login_success", user_id=user["id"])
    return redirect(url_for("portal.dashboard"))


@bp.route("/logout", methods=["POST"])
def logout():
    if g.user is not None:
        security.audit("logout")
        security.revoke_current_session()
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/account/password", methods=["GET", "POST"])
@security.login_required
@security.rate_limit("pwchange", "LOGIN_RATE")
def change_password():
    if request.method == "GET":
        return render_template("password.html")
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    row = db.query_one("SELECT * FROM users WHERE id = ?", (g.user["id"],))
    errors = []
    if not security.verify_password(row["password_hash"], current):
        errors.append("Current password is incorrect.")
    if new != request.form.get("new_password2", ""):
        errors.append("New passwords do not match.")
    if new == current:
        errors.append("New password must be different from the current one.")
    errors += security.validate_password(new, row["username"], row["email"])
    if errors:
        security.audit("password_change_failed")
        return render_template("password.html", errors=errors), 400
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (security.hash_password(new), row["id"]))
    security.revoke_other_sessions(row["id"])             # a stolen session dies when the password changes
    security.audit("password_changed")
    flash("Password updated. Your other sessions were signed out.", "ok")
    return redirect(url_for("portal.dashboard"))
