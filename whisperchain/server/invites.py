"""Invite codes: single-use, expiring, role-bound.

The server stores only SHA-256(code). The plain code is returned once to the
Admin who created it, so a database leak does not reveal usable invites.
"""

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from whisperchain.common import constants as C


def hash_invite_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def create_invite(conn: sqlite3.Connection, roles: list[str], expiry_days: int) -> tuple[str, str]:
    """Insert an invite; return (plain code, expires_at). Caller owns the transaction."""
    roles = sorted(set(roles))
    if not roles:
        raise ValueError("an invite must grant at least one role")
    for role in roles:
        # Admin can never be granted by invite; only init-admin creates Admins.
        if role not in C.INVITABLE_ROLES:
            raise ValueError(f"role not allowed in an invite: {role}")

    code = secrets.token_urlsafe(C.INVITE_CODE_BYTES)
    expires_at = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=expiry_days)
    conn.execute(
        "INSERT INTO invites (code_hash, roles, expires_at, used) VALUES (?, ?, ?, 0)",
        (hash_invite_code(code), json.dumps(roles), expires_at.isoformat()),
    )
    return code, expires_at.isoformat()


def find_usable_invite(conn: sqlite3.Connection, code: str):
    """Return the invite row if it exists, is unused and unexpired, else None."""
    row = conn.execute(
        "SELECT id, roles, expires_at, used FROM invites WHERE code_hash = ?",
        (hash_invite_code(code),),
    ).fetchone()
    if row is None or row["used"]:
        return None
    if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
        return None
    return row
