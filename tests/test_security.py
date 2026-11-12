"""Each test launches an attack and checks that the control blocks it.
Run with:  python -m pytest -v
"""
import json
import re
import time

import jwt
import pytest
from cryptography.fernet import Fernet

from app import db, security
from app.security import totp_now

from conftest import (api_token, bearer, csrf_from, make_app, reset_totp_step, result_id, user_id, web_login)


# =========================================================== perimeter / transport
def test_http_is_redirected_to_https(client):
    r = client.get("/login", base_url="http://localhost")
    assert r.status_code == 301 and r.headers["Location"].startswith("https://")


def test_security_headers_present(client):
    h = client.get("/login").headers
    assert "default-src 'self'" in h["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"
    assert "max-age=31536000" in h["Strict-Transport-Security"]
    assert h["Referrer-Policy"] == "no-referrer"
    assert h["Server"] == "StudentPortal"            # framework and version are hidden
    assert "no-store" in h["Cache-Control"]


def test_host_header_attack_rejected(client):
    assert client.get("/login", base_url="https://evil.example").status_code == 400


def test_oversized_body_rejected(client):
    r = client.post("/login", data={"username": "a" * 100_000})
    assert r.status_code == 413


def test_session_cookie_flags(client):
    cookie = client.get("/login").headers.get("Set-Cookie", "")
    assert cookie.startswith("__Host-portal-session=")
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie


# =========================================================== authentication
def test_protected_pages_require_login(client):
    for path in ("/", "/results", "/fees", "/staff/grades", "/admin/audit", "/account/password"):
        r = client.get(path)
        assert r.status_code == 302 and "/login" in r.headers["Location"], path


def test_login_needs_second_factor(client, app, creds):
    token = csrf_from(client, "/login")
    r = client.post("/login", data={"csrf_token": token, "username": "ama", "password": creds["ama"]["password"]})
    assert r.headers["Location"].endswith("/mfa/verify")
    assert client.get("/results").status_code == 302          # password alone grants nothing


def test_full_login_works(client, app, creds):
    web_login(client, app, creds, "ama")
    assert client.get("/results").status_code == 200


def test_wrong_totp_rejected(client, creds):
    token = csrf_from(client, "/login")
    client.post("/login", data={"csrf_token": token, "username": "ama", "password": creds["ama"]["password"]})
    token = csrf_from(client, "/mfa/verify")
    r = client.post("/mfa/verify", data={"csrf_token": token, "code": "000000"})
    assert r.status_code == 200 and b"Invalid or expired code" in r.data


def test_totp_code_cannot_be_replayed(client, app, creds):
    web_login(client, app, creds, "ama")                      # consumes the current code
    other = app.test_client()
    token = csrf_from(other, "/login")
    other.post("/login", data={"csrf_token": token, "username": "ama", "password": creds["ama"]["password"]})
    token = csrf_from(other, "/mfa/verify")
    r = other.post("/mfa/verify", data={"csrf_token": token, "code": totp_now(creds["ama"]["totp_secret"])})
    assert r.status_code == 200 and b"Invalid or expired code" in r.data


def test_sql_injection_login_fails(client):
    token = csrf_from(client, "/login")
    for payload in ("' OR '1'='1' --", "admin1'--", "x' UNION SELECT 1,2,3,4,5,6,7,8 --"):
        r = client.post("/login", data={"csrf_token": token, "username": payload, "password": "' OR '1'='1"})
        assert r.status_code == 401 and b"Invalid username or password" in r.data


def test_sql_injection_api_token_fails(client):
    r = client.post("/api/token", json={"username": "' OR 1=1 --", "password": "x", "totp": "123456"})
    assert r.status_code == 401


def test_no_user_enumeration(client, creds):
    token = csrf_from(client, "/login")
    unknown = client.post("/login", data={"csrf_token": token, "username": "nobody", "password": "Wrong!Pass#1234"})
    wrong = client.post("/login", data={"csrf_token": token, "username": "ama", "password": "Wrong!Pass#1234"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_data() == wrong.get_data()


def test_account_lockout_after_failures(client, app, creds):
    token = csrf_from(client, "/login")
    for _ in range(5):
        client.post("/login", data={"csrf_token": token, "username": "ama", "password": "Wrong!Pass#1234"})
    r = client.post("/login", data={"csrf_token": token, "username": "ama", "password": creds["ama"]["password"]})
    assert r.status_code == 401                               # correct password is refused while locked
    with app.app_context():
        assert db.query_one("SELECT locked_until FROM users WHERE username='ama'")["locked_until"] > time.time()


def test_login_rate_limit(tmp_path):
    app, _ = make_app(tmp_path, LOGIN_RATE=(3, 60))
    client = app.test_client()
    token = csrf_from(client, "/login")
    codes = [client.post("/login", data={"csrf_token": token, "username": "x", "password": "y"}).status_code
             for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
    assert "Retry-After" in client.post("/login", data={"csrf_token": token}).headers


def test_global_rate_limit_stops_flooding(tmp_path):
    app, _ = make_app(tmp_path, GLOBAL_RATE=(20, 60))
    client = app.test_client()
    codes = [client.get("/login").status_code for _ in range(30)]
    assert codes.count(200) == 20 and codes[-1] == 429


# =========================================================== passwords / registration
@pytest.mark.parametrize("bad", ["short1!A", "alllowercase123!", "NoDigitsHere!!!!", "NoSymbols123456Aa",
                                 "Password123456!x", "aaaaBBBB1111!!!!"])
def test_weak_passwords_rejected(app, bad):
    with app.test_request_context():
        assert security.validate_password(bad, "someone", "someone@example.edu")


def test_strong_password_accepted(app):
    with app.test_request_context():
        assert security.validate_password("Tr0ub4dor&3-horse-battery", "ama", "ama@example.edu") == []


def test_passwords_are_hashed_with_salt(app):
    with app.app_context():
        rows = db.query_all("SELECT password_hash FROM users")
    hashes = [r["password_hash"] for r in rows]
    assert all(h.startswith("pbkdf2:sha256:") for h in hashes) and len(set(hashes)) == len(hashes)


def test_registration_flow_and_no_mass_assignment(client, app):
    token = csrf_from(client, "/register")
    r = client.post("/register", data={
        "csrf_token": token, "username": "newstudent", "email": "new@example.edu", "full_name": "New Student",
        "phone": "+233501112223", "password": "Gr3at!Passphrase#Here", "password2": "Gr3at!Passphrase#Here",
        "role": "admin"})                                       # attacker tries to choose their own role
    assert r.status_code == 302 and r.headers["Location"].endswith("/mfa/setup")
    page = client.get("/mfa/setup").get_data(as_text=True)
    secret = re.search(r'class="secret">([A-Z2-7]+)<', page).group(1)
    token = csrf_from(client, "/mfa/setup")
    r = client.post("/mfa/setup", data={"csrf_token": token, "code": totp_now(secret)})
    assert r.status_code == 302
    with app.app_context():
        row = db.query_one("SELECT role, mfa_enabled FROM users WHERE username='newstudent'")
    assert row["role"] == "student" and row["mfa_enabled"] == 1
    assert client.get("/results").status_code == 200


def test_register_rejects_weak_password(client):
    token = csrf_from(client, "/register")
    r = client.post("/register", data={"csrf_token": token, "username": "weak", "email": "w@example.edu",
                                       "full_name": "Weak User", "password": "password", "password2": "password"})
    assert r.status_code == 400 and b"at least 12 characters" in r.data


def test_register_rejects_script_in_name(client):
    token = csrf_from(client, "/register")
    r = client.post("/register", data={"csrf_token": token, "username": "xssuser", "email": "x@example.edu",
                                       "full_name": "<script>alert(1)</script>",
                                       "password": "Gr3at!Passphrase#Here", "password2": "Gr3at!Passphrase#Here"})
    assert r.status_code == 400


def test_password_change_revokes_other_sessions(app, creds):
    laptop, phone = app.test_client(), app.test_client()
    web_login(laptop, app, creds, "ama")
    time.sleep(0)                                               # second login uses a fresh TOTP step reset
    web_login(phone, app, creds, "ama")
    token = csrf_from(laptop, "/account/password")
    r = laptop.post("/account/password", data={
        "csrf_token": token, "current_password": creds["ama"]["password"],
        "new_password": "N3w!Different#Passphrase", "new_password2": "N3w!Different#Passphrase"})
    assert r.status_code == 302
    assert laptop.get("/results").status_code == 200            # current session survives
    assert phone.get("/results").status_code == 302             # the other session was killed


# =========================================================== sessions / CSRF / XSS
def test_csrf_blocks_forged_post(client, app, creds):
    web_login(client, app, creds, "ama")
    r = client.post("/account/password", data={"current_password": "x", "new_password": "y", "new_password2": "y"})
    assert r.status_code == 400
    r = client.post("/logout", data={"csrf_token": "forged"})
    assert r.status_code == 400


def test_logout_invalidates_session(client, app, creds):
    web_login(client, app, creds, "ama")
    stolen = client.get_cookie("__Host-portal-session")
    token = csrf_from(client, "/fees")
    client.post("/logout", data={"csrf_token": token})
    attacker = app.test_client()
    attacker.set_cookie("__Host-portal-session", stolen.value, domain="localhost")
    assert attacker.get("/results").status_code == 302


def test_idle_timeout(client, app, creds):
    web_login(client, app, creds, "ama")
    with app.app_context():
        db.execute("UPDATE auth_sessions SET last_seen = ?", (int(time.time()) - 3600,))
    assert client.get("/results").status_code == 302


def test_output_is_escaped(client, app, creds):
    web_login(client, app, creds, "ama")
    with app.app_context():
        db.execute("UPDATE users SET full_name = ? WHERE username = 'ama'", ("<script>alert(1)</script>",))
    body = client.get("/").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body and "&lt;script&gt;" in body


def test_no_open_redirect_parameter(client):
    r = client.get("/results?next=https://evil.example")
    assert r.headers["Location"].endswith("/login")


# =========================================================== access control (IAM / RBAC)
def test_student_cannot_see_other_students_result(client, app, creds):
    web_login(client, app, creds, "ama")
    kofi_result = result_id(app, "kofi", "ISM101")
    ama_result = result_id(app, "ama", "ISM101")
    assert client.get("/results/%d" % ama_result).status_code == 200
    assert client.get("/results/%d" % kofi_result).status_code == 404     # IDOR blocked


def test_student_cannot_reach_staff_or_admin(client, app, creds):
    web_login(client, app, creds, "ama")
    assert client.get("/staff/grades").status_code == 403
    assert client.get("/admin/audit").status_code == 403


def test_admin_cannot_read_or_change_grades(client, app, creds):
    web_login(client, app, creds, "admin1")
    assert client.get("/admin/audit").status_code == 200
    assert client.get("/staff/grades").status_code == 403                 # separation of duties


def test_maker_checker_grade_workflow(app, creds):
    lecturer, registry, student = app.test_client(), app.test_client(), app.test_client()
    web_login(lecturer, app, creds, "lecturer1")
    web_login(registry, app, creds, "registry1")
    web_login(student, app, creds, "kofi")
    with app.app_context():
        course = db.query_one("SELECT id FROM courses WHERE code='NET201'")["id"]
    token = csrf_from(lecturer, "/staff/grades")
    r = lecturer.post("/staff/grades", data={"csrf_token": token, "student_id": user_id(app, "kofi"),
                                             "course_id": course, "score": 91})
    assert r.status_code == 302
    assert b"NET201" not in student.get("/results").data                   # hidden until approved
    with app.app_context():
        pending = db.query_one("SELECT id FROM results WHERE status='pending'")["id"]
    assert lecturer.post("/staff/grades/%d/approve" % pending, data={"csrf_token": token}).status_code == 403
    token = csrf_from(registry, "/staff/grades")
    assert registry.post("/staff/grades/%d/approve" % pending, data={"csrf_token": token}).status_code == 302
    assert b"NET201" in student.get("/results").data                       # released after approval


def test_student_cannot_propose_grade(client, app, creds):
    web_login(client, app, creds, "ama")
    token = csrf_from(client, "/fees")
    assert client.post("/staff/grades", data={"csrf_token": token, "student_id": 1, "course_id": 1,
                                              "score": 100}).status_code == 403


def test_fee_payment_validates_amount(client, app, creds):
    web_login(client, app, creds, "ama")
    token = csrf_from(client, "/fees")
    for bad in ("-5", "abc", "0", "99999999"):
        client.post("/fees", data={"csrf_token": token, "amount": bad})
    with app.app_context():
        assert db.query_one("SELECT COUNT(*) AS n FROM payments")["n"] == 0
    client.post("/fees", data={"csrf_token": token, "amount": "100.50"})
    with app.app_context():
        assert db.query_one("SELECT amount_cents FROM payments")["amount_cents"] == 10050


# =========================================================== JWT / API
def test_jwt_flow(client, app, creds):
    token = api_token(client, app, creds, "ama")
    r = client.get("/api/me/results", headers=bearer(token))
    assert r.status_code == 200 and {x["code"] for x in r.get_json()["results"]} == {"ISM101", "NET201"}


def test_api_requires_token(client):
    assert client.get("/api/me/results").status_code == 401
    assert client.get("/api/me/results", headers=bearer("garbage")).status_code == 401


def test_api_idor_blocked(client, app, creds):
    token = api_token(client, app, creds, "ama")
    assert client.get("/api/results/%d" % result_id(app, "kofi", "ISM101"), headers=bearer(token)).status_code == 404
    assert client.get("/api/results/%d" % result_id(app, "ama", "ISM101"), headers=bearer(token)).status_code == 200


def test_jwt_tampering_rejected(client, app, creds):
    token = api_token(client, app, creds, "ama")
    head, body, sig = token.split(".")
    flipped = head + "." + body + "." + ("A" if sig[0] != "A" else "B") + sig[1:]
    assert client.get("/api/me/results", headers=bearer(flipped)).status_code == 401


def _claims(app, **extra):
    now = int(time.time())
    claims = {"iss": "secure-student-portal", "aud": "portal-api", "sub": "1", "role": "admin", "iat": now,
              "nbf": now, "exp": now + 600, "jti": "x"}
    claims.update(extra)
    return claims


def test_jwt_alg_none_rejected(client, app):
    forged = jwt.encode(_claims(app), None, algorithm="none")
    assert client.get("/api/me/results", headers=bearer(forged)).status_code == 401


def test_jwt_wrong_secret_expired_and_wrong_audience_rejected(client, app):
    secret = app.config["JWT_SECRET"]
    for token in (jwt.encode(_claims(app), "attacker-key-attacker-key-attacker-key", algorithm="HS256"),
                  jwt.encode(_claims(app, exp=int(time.time()) - 10), secret, algorithm="HS256"),
                  jwt.encode(_claims(app, aud="some-other-app"), secret, algorithm="HS256")):
        assert client.get("/api/me/results", headers=bearer(token)).status_code == 401


def test_jwt_role_claim_is_ignored(client, app, creds):
    """A validly signed token whose role claim says 'admin' still gets the real user's permissions."""
    forged = jwt.encode(_claims(app, sub=str(user_id(app, "ama")), role="admin", jti="forged1"),
                        app.config["JWT_SECRET"], algorithm="HS256")
    r = client.get("/api/me/results", headers=bearer(forged))
    assert r.status_code == 200 and {x["code"] for x in r.get_json()["results"]} == {"ISM101", "NET201"}


def test_jwt_revocation(client, app, creds):
    token = api_token(client, app, creds, "ama")
    assert client.post("/api/token/revoke", headers=bearer(token)).status_code == 200
    assert client.get("/api/me/results", headers=bearer(token)).status_code == 401


def test_token_requires_valid_totp(client, creds):
    r = client.post("/api/token", json={"username": "ama", "password": creds["ama"]["password"], "totp": "123456"})
    assert r.status_code == 401


def test_token_endpoint_rejects_bad_input(client):
    assert client.post("/api/token", data="not json", content_type="text/plain").status_code == 400
    assert client.post("/api/token", json={"username": ["a"], "password": 1, "totp": None}).status_code == 400


# =========================================================== webhooks (HMAC)
def _make_payment(app, ref="PAY-TEST01", cents=10000, user="ama"):
    with app.app_context():
        db.execute("INSERT INTO payments (student_id, reference, amount_cents, created_at) VALUES (?,?,?,?)",
                   (user_id(app, user), ref, cents, int(time.time())))


def _post_webhook(client, app, body, signature=None, secret=None, timestamp=None):
    raw = json.dumps(body).encode()
    sig = signature or security.sign_webhook(raw, secret or app.config["WEBHOOK_SECRET"], timestamp)
    return client.post("/api/webhooks/payment", data=raw, headers={"X-Signature": sig, "Content-Type": "application/json"})


def _event(ref="PAY-TEST01", cents=10000, event_id="evt_1"):
    return {"event_id": event_id, "reference": ref, "amount_cents": cents, "status": "succeeded"}


def test_webhook_valid_signature_marks_paid(client, app):
    _make_payment(app)
    assert _post_webhook(client, app, _event()).status_code == 200
    with app.app_context():
        assert db.query_one("SELECT status FROM payments")["status"] == "paid"


def test_webhook_forged_signature_rejected(client, app):
    _make_payment(app)
    assert _post_webhook(client, app, _event(), secret="attacker-secret").status_code == 401
    assert client.post("/api/webhooks/payment", json=_event()).status_code == 401      # no signature at all
    with app.app_context():
        assert db.query_one("SELECT status FROM payments")["status"] == "pending"


def test_webhook_replay_is_ignored(client, app):
    _make_payment(app)
    assert _post_webhook(client, app, _event()).get_json()["status"] == "ok"
    assert _post_webhook(client, app, _event()).get_json()["status"] == "duplicate_ignored"


def test_webhook_stale_timestamp_rejected(client, app):
    _make_payment(app)
    assert _post_webhook(client, app, _event(), timestamp=time.time() - 3600).status_code == 401


def test_webhook_amount_mismatch_rejected(client, app):
    _make_payment(app)
    assert _post_webhook(client, app, _event(cents=1)).status_code == 422
    with app.app_context():
        assert db.query_one("SELECT status FROM payments")["status"] == "pending"


def test_webhook_modified_body_rejected(client, app):
    _make_payment(app)
    raw = json.dumps(_event()).encode()
    sig = security.sign_webhook(raw, app.config["WEBHOOK_SECRET"])
    tampered = raw.replace(b"10000", b"99999")
    r = client.post("/api/webhooks/payment", data=tampered, headers={"X-Signature": sig})
    assert r.status_code == 401


# =========================================================== encryption / audit
def test_sensitive_fields_are_encrypted_at_rest(app):
    with app.app_context():
        row = db.query_one("SELECT phone_enc, totp_secret_enc FROM users WHERE username='ama'")
        assert "+233" not in row["phone_enc"] and security.decrypt_field(row["phone_enc"]) == "+233201234567"
        assert security.decrypt_field(row["totp_secret_enc"]).isalnum()
    raw_db = open(app.config["DATABASE"], "rb").read()
    assert b"+233201234567" not in raw_db                      # not even in the database file


def test_encryption_key_rotation(app):
    with app.app_context():
        old_key = app.config["FERNET_KEY"]
        token = security.encrypt_field("secret value")
        app.config["FERNET_KEY"] = Fernet.generate_key().decode() + "," + old_key
        assert security.decrypt_field(token) == "secret value"            # old data still readable
        assert security.decrypt_field(security.encrypt_field("new")) == "new"


def test_tampered_ciphertext_is_rejected(app):
    with app.app_context():
        token = security.encrypt_field("hello")
        assert security.decrypt_field(token[:-4] + "AAAA") is None


def test_audit_chain_detects_tampering(client, app, creds):
    web_login(client, app, creds, "ama")
    with app.app_context():
        ok, bad, count = security.verify_audit_chain()
        assert ok and count > 0
        db.execute("UPDATE audit_log SET detail = 'nothing to see' WHERE id = 1")
        ok, bad, _ = security.verify_audit_chain()
        assert not ok and bad == 1


def test_log_forging_is_neutralised(client):
    token = csrf_from(client, "/login")
    client.post("/login", data={"csrf_token": token, "username": "x\nFAKE EVENT login_success", "password": "y"})
    with app_ctx(client) as app:
        row = db.query_one("SELECT detail FROM audit_log WHERE event='login_failed' ORDER BY id DESC LIMIT 1")
        assert "\n" not in row["detail"]


class app_ctx:
    def __init__(self, client):
        self.app = client.application

    def __enter__(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        return self.app

    def __exit__(self, *exc):
        self.ctx.pop()


# =========================================================== MFA implementation correctness
def test_totp_matches_rfc6238_test_vectors():
    """Official RFC 6238 test vectors (SHA-1 secret '12345678901234567890'), truncated to 6 digits."""
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp_now(secret, at=59) == "287082"
    assert totp_now(secret, at=1111111109) == "081804"
    assert totp_now(secret, at=1234567890) == "005924"


def test_totp_rejects_non_numeric_and_wrong_length_codes():
    secret = security.new_totp_secret()
    for bad in ("", "abcdef", "12345", "1234567", "12 34 5x"):
        assert security.verify_totp(secret, bad) is None
