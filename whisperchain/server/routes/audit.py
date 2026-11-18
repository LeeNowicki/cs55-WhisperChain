"""Audit log routes: the public verification key, and paged reading."""

from fastapi import APIRouter, Depends, Query, Request

from whisperchain.common import constants as C
from whisperchain.common.encoding import b64e
from whisperchain.server import db
from whisperchain.server.auth import CurrentUser, require

router = APIRouter()


@router.get("/audit/public-key")
def audit_public_key(request: Request):
    # Public on purpose: anyone may verify the log's signatures.
    return {"algorithm": "Ed25519", "public_key": b64e(request.app.state.audit.public_key_bytes())}


@router.get("/audit")
def read_audit(
    request: Request,
    after_seq: int = Query(0, ge=0),
    limit: int = Query(C.AUDIT_PAGE_LIMIT, ge=1, le=C.AUDIT_PAGE_LIMIT),
    user: CurrentUser = Depends(require("audit:read")),
    conn=Depends(db.get_db),
):
    # One transaction: record that the log was viewed (by role only), then
    # read a consistent page that already includes that record.
    with db.write_transaction(conn):
        request.app.state.audit.append_audit(conn, "AUDIT_VIEWED", user.acting_role)
        rows = conn.execute(
            "SELECT seq, timestamp, action, role, detail, prev_hash, entry_hash, signature "
            "FROM audit_log WHERE seq > ? ORDER BY seq LIMIT ?",
            (after_seq, limit),
        ).fetchall()
    entries = []
    for row in rows:
        entries.append(dict(row))  # turn the database row into a plain dict
    return {"entries": entries}
