"""SQLite access. Every query in this project uses bound parameters (no string building)."""
from __future__ import annotations

import secrets
import sqlite3
from contextlib import contextmanager

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student','lecturer','registry','admin')),
    phone_enc TEXT,
    totp_secret_enc TEXT NOT NULL,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    last_totp_step INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    last_login_at INTEGER,
    last_login_ip TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    sid_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    ip TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES users(id),
    course_id INTEGER NOT NULL REFERENCES courses(id),
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    grade TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved')),
    entered_by INTEGER NOT NULL REFERENCES users(id),
    approved_by INTEGER REFERENCES users(id),
    updated_at INTEGER NOT NULL,
    UNIQUE (student_id, course_id)
);

CREATE TABLE IF NOT EXISTS fees (
    student_id INTEGER PRIMARY KEY REFERENCES users(id),
    amount_due_cents INTEGER NOT NULL CHECK (amount_due_cents >= 0)
);

CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES users(id),
    reference TEXT NOT NULL UNIQUE,
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','paid')),
    created_at INTEGER NOT NULL,
    paid_at INTEGER
);

CREATE TABLE IF NOT EXISTS webhook_events (
    event_id TEXT PRIMARY KEY,
    received_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    event TEXT NOT NULL,
    user_id INTEGER,
    ip TEXT,
    detail TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE"], isolation_level=None, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)


def init_db() -> None:
    conn = get_db()
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(SCHEMA)


def query_one(sql: str, params=()):
    return get_db().execute(sql, params).fetchone()


def query_all(sql: str, params=()):
    return get_db().execute(sql, params).fetchall()


def execute(sql: str, params=()):
    return get_db().execute(sql, params)


@contextmanager
def transaction():
    """Atomic block. Uses a savepoint if a transaction is already open."""
    conn = get_db()
    if conn.in_transaction:
        name = "sp_" + secrets.token_hex(4)
        conn.execute("SAVEPOINT " + name)
        try:
            yield conn
        except Exception:
            conn.execute("ROLLBACK TO " + name)
            conn.execute("RELEASE " + name)
            raise
        else:
            conn.execute("RELEASE " + name)
    else:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except Exception:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
