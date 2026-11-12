"""Lecturer and registry pages. Grades use a maker-checker workflow: one person proposes, another approves."""
from __future__ import annotations

import time

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from .. import db, security
from .portal import grade_for

bp = Blueprint("staff", __name__, url_prefix="/staff")


@bp.route("/grades", methods=["GET", "POST"])
@security.permission_required("results:read_any")
def grades():
    if request.method == "POST":
        return _propose()
    rows = db.query_all(
        "SELECT r.id, u.full_name, u.username, c.code, r.score, r.grade, r.status,"
        " e.username AS entered_by, a.username AS approved_by"
        " FROM results r JOIN users u ON u.id = r.student_id JOIN courses c ON c.id = r.course_id"
        " JOIN users e ON e.id = r.entered_by LEFT JOIN users a ON a.id = r.approved_by"
        " ORDER BY r.status, u.username, c.code")
    students = db.query_all("SELECT id, username, full_name FROM users WHERE role = 'student' AND active = 1 ORDER BY username")
    courses = db.query_all("SELECT id, code, title FROM courses ORDER BY code")
    return render_template("staff_grades.html", rows=rows, students=students, courses=courses)


def _propose():
    if not security.can("grades:propose"):
        security.audit("permission_denied", detail="grades:propose %s" % request.path)
        abort(403)
    try:
        student_id = int(request.form["student_id"])
        course_id = int(request.form["course_id"])
        score = int(request.form["score"])
    except (KeyError, ValueError):
        abort(400)
    if not 0 <= score <= 100:
        abort(400)
    student = db.query_one("SELECT id FROM users WHERE id = ? AND role = 'student' AND active = 1", (student_id,))
    course = db.query_one("SELECT id FROM courses WHERE id = ?", (course_id,))
    if student is None or course is None:
        abort(400)
    db.execute(
        "INSERT INTO results (student_id, course_id, score, grade, status, entered_by, updated_at)"
        " VALUES (?,?,?,?, 'pending', ?, ?)"
        " ON CONFLICT(student_id, course_id) DO UPDATE SET score = excluded.score, grade = excluded.grade,"
        " status = 'pending', entered_by = excluded.entered_by, approved_by = NULL, updated_at = excluded.updated_at",
        (student_id, course_id, score, grade_for(score), g.user["id"], int(time.time())))
    security.audit("grade_proposed", detail="student %d course %d score %d" % (student_id, course_id, score))
    flash("Grade submitted for registry approval.", "ok")
    return redirect(url_for("staff.grades"))


@bp.route("/grades/<int:result_id>/approve", methods=["POST"])
@security.permission_required("grades:approve")
def approve(result_id: int):
    with db.transaction() as conn:
        row = conn.execute("SELECT * FROM results WHERE id = ?", (result_id,)).fetchone()
        if row is None or row["status"] != "pending":
            abort(404)
        if row["entered_by"] == g.user["id"]:
            security.audit("self_approval_blocked", detail="result %d" % result_id)
            abort(403)                                     # four-eyes rule
        conn.execute("UPDATE results SET status = 'approved', approved_by = ?, updated_at = ? WHERE id = ?",
                     (g.user["id"], int(time.time()), result_id))
    security.audit("grade_approved", detail="result %d" % result_id)
    flash("Grade approved and released to the student.", "ok")
    return redirect(url_for("staff.grades"))
