"""Student pages: dashboard, results and fees."""
from __future__ import annotations

import secrets
import time
from decimal import Decimal, InvalidOperation

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from .. import db, security

bp = Blueprint("portal", __name__)


def grade_for(score: int) -> str:
    for cutoff, letter in ((80, "A"), (70, "B"), (60, "C"), (50, "D"), (40, "E")):
        if score >= cutoff:
            return letter
    return "F"


def fee_position(student_id: int):
    due = db.query_one("SELECT amount_due_cents FROM fees WHERE student_id = ?", (student_id,))
    paid = db.query_one("SELECT COALESCE(SUM(amount_cents),0) AS s FROM payments WHERE student_id = ? AND status='paid'",
                        (student_id,))["s"]
    due_cents = due["amount_due_cents"] if due else 0
    return due_cents, paid, max(due_cents - paid, 0)


def money(cents: int) -> str:
    return "GHS {:,.2f}".format(cents / 100)


@bp.app_template_filter("money")
def _money_filter(cents):
    return money(int(cents))


@bp.app_template_filter("when")
def _when_filter(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) if ts else "never"


@bp.route("/")
@security.login_required
def dashboard():
    phone = security.decrypt_field(g.user["phone_enc"])
    masked = ("*" * max(len(phone) - 3, 0) + phone[-3:]) if phone else None
    return render_template("dashboard.html", phone=masked)


@bp.route("/results")
@security.permission_required("results:read_own")
def results():
    rows = db.query_all(
        "SELECT r.id, c.code, c.title, r.score, r.grade FROM results r JOIN courses c ON c.id = r.course_id"
        " WHERE r.student_id = ? AND r.status = 'approved' ORDER BY c.code", (g.user["id"],))
    return render_template("results.html", rows=rows)


@bp.route("/results/<int:result_id>")
@security.permission_required("results:read_own")
def result_detail(result_id: int):
    row = db.query_one(
        "SELECT r.id, r.student_id, r.score, r.grade, r.status, r.updated_at, c.code, c.title"
        " FROM results r JOIN courses c ON c.id = r.course_id WHERE r.id = ?", (result_id,))
    if row is None:
        abort(404)
    if row["student_id"] != g.user["id"] or row["status"] != "approved":
        # Object-level authorisation. We answer 404, not 403, so attackers learn nothing about other records.
        security.audit("idor_blocked", detail="result %d" % result_id)
        abort(404)
    return render_template("result_detail.html", r=row)


@bp.route("/fees", methods=["GET", "POST"])
@security.permission_required("fees:read_own")
def fees():
    due, paid, outstanding = fee_position(g.user["id"])
    if request.method == "POST":
        if "fees:pay" not in security.permissions_for(g.user["role"]):
            abort(403)
        try:
            amount = Decimal(request.form.get("amount", "").strip())
            cents = int((amount * 100).to_integral_exact())
        except (InvalidOperation, ValueError):
            cents = 0
        if cents <= 0 or cents > outstanding:
            flash("Enter an amount between 0.01 and your outstanding balance.", "error")
        else:
            reference = "PAY-" + secrets.token_hex(6).upper()
            db.execute("INSERT INTO payments (student_id, reference, amount_cents, created_at) VALUES (?,?,?,?)",
                       (g.user["id"], reference, cents, int(time.time())))
            security.audit("payment_initiated", detail="%s %d" % (reference, cents))
            flash("Payment %s created. It will show as paid once the payment provider confirms it." % reference, "ok")
        return redirect(url_for("portal.fees"))
    payments = db.query_all("SELECT reference, amount_cents, status, created_at FROM payments"
                            " WHERE student_id = ? ORDER BY id DESC", (g.user["id"],))
    return render_template("fees.html", due=due, paid=paid, outstanding=outstanding, payments=payments)
