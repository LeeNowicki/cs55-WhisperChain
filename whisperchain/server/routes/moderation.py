"""Flagging (Recipients) and the moderation queue (Moderators).

Moderators see a flagged message's ciphertext and their OWN wrapped copy of
its content key, which the recipient's client created at flag time. They
never see who received it, who sent it, or its token.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from whisperchain.common import constants as C
from whisperchain.common.encoding import b64d, b64e
from whisperchain.common.envelope import parse_header
from whisperchain.server import db
from whisperchain.server.auth import CurrentUser, require
from whisperchain.server.ownership import get_owned_message

router = APIRouter()


class FlagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="", max_length=C.FLAG_REASON_MAX_CHARS)
    # moderator key_id -> content key wrapped (RSA-OAEP) to that key.
    # Empty when the recipient could not decrypt the message.
    wrapped_keys: dict[str, str] = Field(default_factory=dict, max_length=100)


def _is_active_moderator_key(conn, key_id: str) -> bool:
    row = conn.execute(
        """
        SELECT 1 FROM public_keys k
        JOIN users u ON u.id = k.user_id
        JOIN user_roles r ON r.user_id = u.id AND r.role = 'Moderator'
        WHERE k.key_id = ? AND k.status = 'active' AND u.active = 1
        """,
        (key_id,),
    ).fetchone()
    return row is not None


@router.post("/messages/{message_id}/flag")
def flag_message(
    message_id: str,
    body: FlagRequest,
    request: Request,
    user: CurrentUser = Depends(require("message:flag")),
    conn=Depends(db.get_db),
):
    # Decode and size-check the wrapped keys before touching the database.
    wrapped = {}
    for key_id, value in body.wrapped_keys.items():
        try:
            data = b64d(value)
        except ValueError:
            raise HTTPException(status_code=400, detail="wrapped key is not valid base64")
        if len(data) != C.WRAPPED_KEY_BYTES:
            raise HTTPException(status_code=400, detail="wrapped key has the wrong length")
        wrapped[key_id] = data

    flag_id = str(uuid.uuid4())
    with db.write_transaction(conn):
        # Ownership: only the recipient may flag; anyone else gets 404.
        get_owned_message(conn, message_id, user.id)
        if conn.execute("SELECT 1 FROM flags WHERE message_id = ?", (message_id,)).fetchone():
            raise HTTPException(status_code=409, detail="message is already flagged")
        for key_id in wrapped:
            if not _is_active_moderator_key(conn, key_id):
                raise HTTPException(status_code=400, detail="a wrapped key is not for an active moderator; refresh your directory")

        conn.execute(
            "INSERT INTO flags (id, message_id, reason, status, created_at) VALUES (?, ?, ?, 'open', ?)",
            (flag_id, message_id, body.reason, db.now_iso()),
        )
        for key_id, data in wrapped.items():
            conn.execute("INSERT INTO flag_keys (flag_id, moderator_key_id, wrapped_key) VALUES (?, ?, ?)",
                         (flag_id, key_id, data))
        conn.execute("UPDATE messages SET status = 'flagged' WHERE id = ?", (message_id,))
        # Audited by flag id only. The alert rules run from this append.
        request.app.state.audit.append_audit(conn, "MESSAGE_FLAGGED", user.acting_role, f"flag: {flag_id}")
    return {"flag_id": flag_id, "moderator_copies": len(wrapped)}


@router.get("/mod/flags")
def flag_queue(user: CurrentUser = Depends(require("flag:queue")), conn=Depends(db.get_db)):
    # Deliberately NO recipient identity, message id, or token hash.
    rows = conn.execute(
        "SELECT f.id, m.round, f.status, f.reason, f.created_at "
        "FROM flags f JOIN messages m ON m.id = f.message_id ORDER BY f.created_at, f.id"
    ).fetchall()
    flags = []
    for row in rows:
        flags.append(dict(row))
    return {"flags": flags}


def _get_flag(conn, flag_id: str):
    row = conn.execute(
        "SELECT f.id, f.status, f.reason, f.created_at, m.round, m.envelope, m.token_hash "
        "FROM flags f JOIN messages m ON m.id = f.message_id WHERE f.id = ?",
        (flag_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="flag not found")
    return row


@router.get("/mod/flags/{flag_id}")
def review_flag(
    flag_id: str,
    request: Request,
    user: CurrentUser = Depends(require("flag:review")),
    conn=Depends(db.get_db),
):
    with db.write_transaction(conn):
        row = _get_flag(conn, flag_id)
        # Only THIS moderator's copy of the content key (if any).
        mine = conn.execute(
            "SELECT fk.wrapped_key FROM flag_keys fk JOIN public_keys k ON k.key_id = fk.moderator_key_id "
            "WHERE fk.flag_id = ? AND k.user_id = ? AND k.status = 'active'",
            (flag_id, user.id),
        ).fetchone()
        request.app.state.audit.append_audit(conn, "FLAG_REVIEWED", user.acting_role, f"flag: {flag_id}")

    parts = parse_header(row["envelope"])
    if mine is None:
        my_wrapped_key = None  # the recipient made no copy for this moderator
    else:
        my_wrapped_key = b64e(mine["wrapped_key"])
    # Everything needed to rebuild the AAD (version, key_id, round) and
    # decrypt, but nothing that identifies the recipient or the token.
    return {
        "id": row["id"], "round": row["round"], "status": row["status"],
        "reason": row["reason"], "created_at": row["created_at"],
        "version": parts["version"], "key_id": parts["key_id"],
        "nonce": b64e(parts["nonce"]), "ciphertext": b64e(parts["ciphertext"]),
        "wrapped_key": my_wrapped_key,
    }


def _resolve(conn, flag_id: str, new_status: str):
    row = _get_flag(conn, flag_id)
    if row["status"] != "open":
        raise HTTPException(status_code=409, detail=f"flag is already {row['status']}")
    conn.execute("UPDATE flags SET status = ? WHERE id = ?", (new_status, flag_id))
    return row


@router.post("/mod/flags/{flag_id}/freeze")
def freeze_flag(
    flag_id: str,
    request: Request,
    user: CurrentUser = Depends(require("flag:resolve")),
    conn=Depends(db.get_db),
):
    """Freeze the token tied to the flagged message.

    That token is already spent, so this records the moderation decision and
    keeps that exact token unacceptable (even as a "retry"). It cannot block
    the sender in later rounds: their future tokens are blind-signed and
    unlinkable, and the server keeps no token-to-user mapping by design.
    """
    with db.write_transaction(conn):
        row = _resolve(conn, flag_id, "actioned")
        conn.execute("INSERT OR IGNORE INTO frozen_tokens (token_hash, flag_id, frozen_at) VALUES (?, ?, ?)",
                     (row["token_hash"], flag_id, db.now_iso()))
        request.app.state.audit.append_audit(conn, "TOKEN_FROZEN", user.acting_role, f"flag: {flag_id}")
    return {"id": flag_id, "status": "actioned"}


@router.post("/mod/flags/{flag_id}/dismiss")
def dismiss_flag(
    flag_id: str,
    request: Request,
    user: CurrentUser = Depends(require("flag:resolve")),
    conn=Depends(db.get_db),
):
    with db.write_transaction(conn):
        _resolve(conn, flag_id, "dismissed")
        request.app.state.audit.append_audit(conn, "FLAG_DISMISSED", user.acting_role, f"flag: {flag_id}")
    return {"id": flag_id, "status": "dismissed"}
