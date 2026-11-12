"""JSON API: JWT-protected endpoints and an HMAC-signed payment webhook."""
from __future__ import annotations

import json
import sqlite3
import time

from flask import Blueprint, g, jsonify, request

from .. import authn, db, security

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/token", methods=["POST"])
@security.csrf_exempt                                   # no cookies are involved here, so CSRF does not apply
@security.rate_limit("api_token", "API_TOKEN_RATE")
def token():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="invalid_request"), 400
    username, password, code = data.get("username"), data.get("password"), data.get("totp")
    if not all(isinstance(v, str) for v in (username, password, code)):
        return jsonify(error="invalid_request"), 400
    user = authn.check_credentials(username.strip(), password)
    if user is None:
        return jsonify(error="invalid_credentials"), 401
    if not user["mfa_enabled"]:
        return jsonify(error="mfa_enrolment_required"), 403   # tokens are only issued to MFA-enrolled users
    if not authn.verify_second_factor(user, code):
        return jsonify(error="invalid_credentials"), 401
    token_value, jti, exp = security.issue_token(user)
    security.audit("api_token_issued", user_id=user["id"], detail=jti)
    return jsonify(access_token=token_value, token_type="Bearer", expires_in=exp - int(time.time()))


@bp.route("/token/revoke", methods=["POST"])
@security.csrf_exempt
@security.rate_limit("api", "API_RATE")
@security.jwt_required()
def revoke():
    claims = g.jwt_claims
    db.execute("INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)", (claims["jti"], claims["exp"]))
    db.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (int(time.time()),))
    security.audit("api_token_revoked", user_id=g.api_user["id"], detail=claims["jti"])
    return jsonify(status="revoked")


@bp.route("/me/results")
@security.rate_limit("api", "API_RATE", methods=("GET", "POST"))
@security.jwt_required("results:read_own")
def my_results():
    rows = db.query_all(
        "SELECT r.id, c.code, c.title, r.score, r.grade FROM results r JOIN courses c ON c.id = r.course_id"
        " WHERE r.student_id = ? AND r.status = 'approved' ORDER BY c.code", (g.api_user["id"],))
    return jsonify(results=[dict(r) for r in rows])


@bp.route("/results/<int:result_id>")
@security.rate_limit("api", "API_RATE", methods=("GET", "POST"))
@security.jwt_required("results:read_own")
def result_detail(result_id: int):
    row = db.query_one(
        "SELECT r.id, r.student_id, r.score, r.grade, c.code, c.title FROM results r"
        " JOIN courses c ON c.id = r.course_id WHERE r.id = ? AND r.status = 'approved'", (result_id,))
    if row is None or row["student_id"] != g.api_user["id"]:
        if row is not None:
            security.audit("idor_blocked", user_id=g.api_user["id"], detail="api result %d" % result_id)
        return jsonify(error="not_found"), 404
    return jsonify(id=row["id"], code=row["code"], title=row["title"], score=row["score"], grade=row["grade"])


@bp.route("/webhooks/payment", methods=["POST"])
@security.csrf_exempt                                   # authenticated by HMAC signature instead of a cookie
@security.rate_limit("webhook", "WEBHOOK_RATE")
def payment_webhook():
    raw = request.get_data(cache=True)
    ok, reason = security.verify_webhook(raw, request.headers.get("X-Signature", ""))
    if not ok:
        security.audit("webhook_rejected", detail=reason)
        return jsonify(error="invalid_signature"), 401
    try:
        event = json.loads(raw)
        event_id, reference = str(event["event_id"])[:80], str(event["reference"])[:40]
        amount, status = int(event["amount_cents"]), str(event["status"])
    except (ValueError, KeyError, TypeError):
        return jsonify(error="invalid_payload"), 400
    try:
        with db.transaction() as conn:
            # The unique event id makes delivery idempotent: a replayed event is acknowledged but ignored.
            conn.execute("INSERT INTO webhook_events (event_id, received_at) VALUES (?, ?)", (event_id, int(time.time())))
            payment = conn.execute("SELECT * FROM payments WHERE reference = ?", (reference,)).fetchone()
            if payment is None or payment["status"] != "pending" or payment["amount_cents"] != amount:
                security.audit("webhook_mismatch", detail=reference)
                return jsonify(error="payment_mismatch"), 422
            if status == "succeeded":
                conn.execute("UPDATE payments SET status = 'paid', paid_at = ? WHERE id = ?",
                             (int(time.time()), payment["id"]))
    except sqlite3.IntegrityError:
        return jsonify(status="duplicate_ignored"), 200
    if status == "succeeded":
        security.audit("payment_confirmed", user_id=payment["student_id"], detail=reference)
    return jsonify(status="ok")
