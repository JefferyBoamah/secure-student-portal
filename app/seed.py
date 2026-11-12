"""Demo data: four users (one per role), courses, results and a fee balance."""
from __future__ import annotations

import time

from . import db, security

DEMO_USERS = [
    # username, full name, role, email, password, phone
    ("admin1", "Ada Admin", "admin", "admin1@example.edu", "Adm1n!Portal#2026x", None),
    ("registry1", "Reggie Registry", "registry", "registry1@example.edu", "Reg!stry#Portal2026", None),
    ("lecturer1", "Lola Lecturer", "lecturer", "lecturer1@example.edu", "Lect!rer#Portal2026", None),
    ("ama", "Ama Mensah", "student", "ama@example.edu", "Ama!Strong#Pass2026", "+233201234567"),
    ("kofi", "Kofi Boateng", "student", "kofi@example.edu", "Kofi!Strong#Pass2026", "+233241234567"),
]


def seed_demo() -> dict:
    """Create demo accounts (MFA already enrolled). Returns the credentials so scripts can print them."""
    now = int(time.time())
    creds = {}
    ids = {}
    for username, name, role, email, password, phone in DEMO_USERS:
        if db.query_one("SELECT 1 FROM users WHERE username = ?", (username,)):
            continue
        secret = security.new_totp_secret()
        cur = db.execute(
            "INSERT INTO users (username, email, full_name, password_hash, role, phone_enc, totp_secret_enc,"
            " mfa_enabled, created_at) VALUES (?,?,?,?,?,?,?,1,?)",
            (username, email, name, security.hash_password(password), role,
             security.encrypt_field(phone) if phone else None, security.encrypt_field(secret), now))
        ids[username] = cur.lastrowid
        creds[username] = {"password": password, "totp_secret": secret, "role": role}
    for code, title in (("ISM101", "Information Security Management"), ("NET201", "Computer Networks"),
                        ("DBS301", "Database Systems")):
        db.execute("INSERT OR IGNORE INTO courses (code, title) VALUES (?, ?)", (code, title))
    if "ama" in ids and "lecturer1" in ids and "registry1" in ids:
        courses = {r["code"]: r["id"] for r in db.query_all("SELECT id, code FROM courses")}
        scores = {"ama": {"ISM101": 84, "NET201": 72}, "kofi": {"ISM101": 65, "DBS301": 58}}
        for student, by_course in scores.items():
            for code, score in by_course.items():
                grade = "A" if score >= 80 else "B" if score >= 70 else "C" if score >= 60 else "D"
                db.execute(
                    "INSERT INTO results (student_id, course_id, score, grade, status, entered_by, approved_by, updated_at)"
                    " VALUES (?,?,?,?, 'approved', ?, ?, ?)",
                    (ids[student], courses[code], score, grade, ids["lecturer1"], ids["registry1"], now))
        db.execute("INSERT OR IGNORE INTO fees (student_id, amount_due_cents) VALUES (?, ?)", (ids["ama"], 450000))
        db.execute("INSERT OR IGNORE INTO fees (student_id, amount_due_cents) VALUES (?, ?)", (ids["kofi"], 450000))
    return creds
