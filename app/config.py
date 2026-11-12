"""Central configuration. Every security-relevant setting is visible here."""
from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    INSTANCE_DIR = BASE_DIR / "instance"
    DATABASE = str(INSTANCE_DIR / "portal.db")
    LOG_FILE = str(INSTANCE_DIR / "security.log")
    LOG_TO_FILE = True

    # Secrets: loaded from environment variables or instance/secrets.json
    # (see security.load_secrets). Never hard-code them in source control.
    SECRET_KEY = None
    JWT_SECRET = None
    FERNET_KEY = None          # comma-separated list allows key rotation
    WEBHOOK_SECRET = None

    # ---- Perimeter ----
    ALLOWED_HOSTS = ("localhost", "127.0.0.1")   # blocks Host-header attacks / phishing relays
    FORCE_HTTPS = True                             # redirect + HSTS (anti man-in-the-middle)
    BEHIND_PROXY = os.environ.get("PORTAL_BEHIND_PROXY") == "1"
    MAX_CONTENT_LENGTH = 64 * 1024                 # reject oversized request bodies (413)
    PUBLIC_HOST = "localhost"
    HTTPS_PORT = 5000
    HTTP_REDIRECT_PORT = 5080

    # ---- Sessions and cookies ----
    SESSION_COOKIE_NAME = "__Host-portal-session"  # __Host- prefix: Secure, Path=/, no Domain
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_IDLE_SECONDS = 15 * 60                 # server-side idle timeout
    SESSION_ABSOLUTE_SECONDS = 8 * 3600            # server-side absolute timeout
    PRE_MFA_SECONDS = 5 * 60

    # ---- Passwords and lockout ----
    PASSWORD_MIN_LENGTH = 12
    PBKDF2_ITERATIONS = 600_000                    # OWASP guidance for PBKDF2-HMAC-SHA256
    LOGIN_MAX_FAILURES = 5
    LOCKOUT_SECONDS = 15 * 60

    # ---- Rate limits: (max requests, window in seconds) per client IP ----
    GLOBAL_RATE = (300, 60)
    LOGIN_RATE = (10, 60)
    REGISTER_RATE = (5, 300)
    MFA_RATE = (10, 60)
    API_TOKEN_RATE = (10, 60)
    API_RATE = (60, 60)
    WEBHOOK_RATE = (30, 60)

    # ---- JWT ----
    JWT_ISSUER = "secure-student-portal"
    JWT_AUDIENCE = "portal-api"
    JWT_TTL_SECONDS = 15 * 60

    # ---- Webhooks ----
    WEBHOOK_TOLERANCE_SECONDS = 5 * 60
