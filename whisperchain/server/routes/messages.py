"""Anonymous send, and the recipient's inbox.

POST /messages is deliberately PUBLIC: it has no login dependency and never
looks at who is calling. The only thing that authorizes a send is the
one-time, blind-signed token in the request body.
"""

import hashlib
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from whisperchain.common import blind
from whisperchain.common import constants as C
from whisperchain.common.encoding import b64_to_int, b64d, b64e
from whisperchain.common.envelope import EnvelopeError, parse_header
from whisperchain.server import db, rounds
from whisperchain.server.auth import CurrentUser, require
from whisperchain.server.ratelimit import rate_limited

router = APIRouter()

_ENVELOPE_B64_LEN = 4 * ((C.ENVELOPE_BYTES + 2) // 3)  # base64 length of 1453 bytes


class SendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipient: str = Field(max_length=64)
    round: int
    envelope: str = Field(max_length=_ENVELOPE_B64_LEN)
    t: str = Field(max_length=64)
    s: str = Field(max_length=600)


class SpendRejected(Exception):
    """Raised inside the transaction; handled (and audited) after rollback."""

    def __init__(self, reason: str, status: int, message: str):
        super().__init__(message)
        self.reason = reason
        self.status = status
        self.message = message


def _active_recipient_id(conn, username: str, key_id: str):
    """The recipient's user id, if they are active, hold Recipient, and
    key_id is their ACTIVE key. Otherwise None."""
    row = conn.execute(
        """
        SELECT u.id FROM users u
        JOIN user_roles r ON r.user_id = u.id AND r.role = 'Recipient'
        JOIN public_keys k ON k.user_id = u.id
        WHERE u.username = ? AND u.active = 1 AND k.key_id = ? AND k.status = 'active'
        """,
        (username, key_id),
    ).fetchone()
    if row is None:
        return None
    return row["id"]


def _accept_or_reject(conn, body: SendRequest, envelope: bytes, parts: dict, t: bytes, s: int) -> str:
    """Steps 2-7 of the validation order. Returns "accepted" or "duplicate";
    raises SpendRejected. Must run inside write_transaction."""
    # 2. Round exists and is open (tokens from closed rounds are dead).
    round_row = rounds.get_round(conn, body.round)
    if round_row is None or round_row["status"] != "open":
        raise SpendRejected("closed_round", 409, "that round is closed; request a new token")

    # 3. Recipient is valid and the envelope is for their ACTIVE key. Checked
    #    BEFORE the token, so a stale directory never wastes a token.
    recipient_id = _active_recipient_id(conn, body.recipient, parts["key_id"])
    if recipient_id is None:
        raise SpendRejected("bad_recipient", 409,
                            "recipient or key is not valid; refresh your directory (keys sync)")

    # 4. Token signature valid under THIS round's key.
    n, e = rounds.public_numbers(round_row)
    if not blind.verify_token(t, s, n, e):
        raise SpendRejected("bad_signature", 403, "token signature is invalid")

    token_hash = blind.token_hash(t)

    # 5. Frozen by a moderator?
    if conn.execute("SELECT 1 FROM frozen_tokens WHERE token_hash = ?", (token_hash,)).fetchone():
        raise SpendRejected("frozen", 403, "this token has been frozen by a moderator")

    # 6. Already spent? Same envelope = harmless client retry; different = replay.
    envelope_hash = hashlib.sha256(envelope).hexdigest()
    spent = conn.execute("SELECT envelope_hash FROM messages WHERE token_hash = ?", (token_hash,)).fetchone()
    if spent is not None:
        if spent["envelope_hash"] == envelope_hash:
            return "duplicate"
        raise SpendRejected("replay", 409, "this token has already been used")

    # 7. Store. The UNIQUE(token_hash) column is the spent-token registry.
    conn.execute(
        "INSERT INTO messages (id, recipient_id, key_id, round, envelope, envelope_hash, token_hash, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'delivered')",
        (str(uuid.uuid4()), recipient_id, parts["key_id"], body.round, envelope, envelope_hash, token_hash),
    )
    return "accepted"


@router.post("/messages", dependencies=[Depends(rate_limited("send"))])
def send_message(body: SendRequest, request: Request, conn=Depends(db.get_db)):
    # 1. Cheapest checks first: sizes and envelope format. No DB work yet.
    length = request.headers.get("content-length")
    if length is not None and length.isdigit():
        if int(length) > C.MAX_SEND_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="request too large")
    try:
        envelope = b64d(body.envelope)
        parts = parse_header(envelope)  # exact length, version, key id
        t = b64d(body.t)
        s = b64_to_int(body.s)
    except (ValueError, EnvelopeError) as exc:
        raise HTTPException(status_code=400, detail=f"malformed request: {exc}")
    if len(t) != C.TOKEN_T_BYTES:
        raise HTTPException(status_code=400, detail="malformed token")

    audit = request.app.state.audit
    try:
        with db.write_transaction(conn):
            outcome = _accept_or_reject(conn, body, envelope, parts, t, s)
            if outcome == "accepted":
                # Same transaction as the insert: both happen or neither does.
                audit.append_audit(conn, "MESSAGE_SENT", C.ROLE_SENDER, f"round: {body.round}")
    except SpendRejected as rejected:
        # The transaction above rolled back, so nothing was written and the
        # token was not consumed. Audit at most once per reason per window,
        # but count every rejection for the REJECTION_BURST alert.
        should_audit = request.app.state.rejections.record(rejected.reason)
        alerts = request.app.state.alerts
        if should_audit or alerts.burst_threshold_reached():
            with db.write_transaction(conn):
                if should_audit:
                    audit.append_audit(conn, "SPEND_REJECTED", C.ROLE_SENDER, f"reason: {rejected.reason}")
                alerts.check_rejection_burst(audit, conn)
        raise HTTPException(status_code=rejected.status,
                            detail={"message": rejected.message, "reason": rejected.reason})

    # Never return the message id: the sender has no use for it, and it would
    # be a handle linking this request to a stored message.
    return {"status": "accepted"}


@router.get("/inbox")
def inbox(request: Request, user: CurrentUser = Depends(require("inbox:read")), conn=Depends(db.get_db)):
    with db.write_transaction(conn):
        # Scoped by the SESSION user's id, never a request parameter. Within
        # a round the order is random, so position reveals nothing about
        # arrival order (and therefore nothing about send timing).
        rows = conn.execute(
            "SELECT id, round, key_id, envelope, status FROM messages "
            "WHERE recipient_id = ? ORDER BY round, RANDOM()",
            (user.id,),
        ).fetchall()
        request.app.state.audit.append_audit(conn, "INBOX_FETCHED", user.acting_role)
    message_list = []
    for row in rows:
        message_list.append({
            "id": row["id"],
            "round": row["round"],
            "key_id": row["key_id"],
            "envelope": b64e(row["envelope"]),
            "status": row["status"],
        })
    return {"messages": message_list}
