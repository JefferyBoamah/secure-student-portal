"""Administrator pages. Admins can read the audit trail but cannot read or change grades."""
from __future__ import annotations

from flask import Blueprint, render_template

from .. import db, security

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/audit")
@security.permission_required("audit:read")
def audit_view():
    ok, bad_id, checked = security.verify_audit_chain()
    rows = db.query_all("SELECT a.id, a.ts, a.event, a.ip, a.detail, u.username FROM audit_log a"
                        " LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT 100")
    return render_template("admin_audit.html", rows=rows, ok=ok, bad_id=bad_id, checked=checked)
