import re
import sys
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app, db          # noqa: E402
from app.security import totp_now       # noqa: E402
from app.seed import seed_demo          # noqa: E402


def make_app(tmp_path, **overrides):
    config = {
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
        "LOG_TO_FILE": False,
        "PREFERRED_URL_SCHEME": "https",      # test client talks HTTPS by default
        "PBKDF2_ITERATIONS": 1000,            # fast hashing for tests only
        "SECRET_KEY": "test-secret-key-not-for-production",
        "JWT_SECRET": "test-jwt-secret-with-enough-length-1234567890",
        "FERNET_KEY": Fernet.generate_key().decode(),
        "WEBHOOK_SECRET": "test-webhook-secret",
    }
    config.update(overrides)
    app = create_app(config)
    with app.app_context():
        creds = seed_demo()
    return app, creds


@pytest.fixture
def env(tmp_path):
    app, creds = make_app(tmp_path)
    return app, creds


@pytest.fixture
def app(env):
    return env[0]


@pytest.fixture
def creds(env):
    return env[1]


@pytest.fixture
def client(app):
    return app.test_client()


# ---------------------------------------------------------------- helpers
def csrf_from(client, path):
    html = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "no CSRF token on " + path
    return match.group(1)


def reset_totp_step(app, username):
    with app.app_context():
        db.execute("UPDATE users SET last_totp_step = 0 WHERE username = ?", (username,))


def web_login(client, app, creds, username, reset=True):
    """Full password + TOTP login through the real HTML forms."""
    if reset:
        reset_totp_step(app, username)
    token = csrf_from(client, "/login")
    r = client.post("/login", data={"csrf_token": token, "username": username,
                                    "password": creds[username]["password"]})
    assert r.status_code == 302 and r.headers["Location"].endswith("/mfa/verify"), r.status_code
    token = csrf_from(client, "/mfa/verify")
    r = client.post("/mfa/verify", data={"csrf_token": token, "code": totp_now(creds[username]["totp_secret"])})
    assert r.status_code == 302, "MFA step failed"
    return r


def api_token(client, app, creds, username, reset=True):
    if reset:
        reset_totp_step(app, username)
    r = client.post("/api/token", json={"username": username, "password": creds[username]["password"],
                                        "totp": totp_now(creds[username]["totp_secret"])})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()["access_token"]


def user_id(app, username):
    with app.app_context():
        return db.query_one("SELECT id FROM users WHERE username = ?", (username,))["id"]


def result_id(app, username, code):
    with app.app_context():
        row = db.query_one("SELECT r.id FROM results r JOIN users u ON u.id = r.student_id"
                           " JOIN courses c ON c.id = r.course_id WHERE u.username = ? AND c.code = ?",
                           (username, code))
        return row["id"]


def bearer(token):
    return {"Authorization": "Bearer " + token}


__all__ = ["csrf_from", "web_login", "api_token", "user_id", "result_id", "bearer", "reset_totp_step", "time"]
