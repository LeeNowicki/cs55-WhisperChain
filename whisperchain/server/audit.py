"""Server-side audit log writer.

Privacy rule: an entry NEVER contains a user id, username, token, token
hash, message id, or IP address. `detail` is restricted to a small set of
formats (checked below), so a programming mistake cannot leak an identity
into the permanent, append-only log.
"""

import re
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from whisperchain.common import constants as C
from whisperchain.common.audit_chain import compute_entry_hash
from whisperchain.common.encoding import b64e
from whisperchain.server import db

_ROLE = r"(Sender|Recipient|Moderator|Admin)"
_ROLE_LIST = rf"{_ROLE}(,{_ROLE})*"

# The ONLY shapes `detail` may take.
_ALLOWED_DETAIL = [
    r"",                                   # nothing
    r"round: \d+",                         # a round number
    r"flag: [0-9a-f-]{36}",                # a flag id (uuid4)
    r"rule: [A-Z_]+",                      # an alert rule name
    rf"roles: {_ROLE_LIST}",               # a role list
    r"reason: [a-z_]+",                    # a spend-reject reason
    r"permission: [a-z_]+:[a-z_]+",        # permission attempted (ACCESS_DENIED)
]
# The `role` column: who acted, by role only.
_ALLOWED_ROLE = rf"System|none|{_ROLE_LIST}"

ACTIONS = {
    "USER_REGISTERED", "KEY_REGISTERED", "KEY_REVOKED", "INVITE_CREATED", "ROLES_CHANGED",
    "USER_DEACTIVATED", "ROUND_STARTED", "TOKEN_ISSUED", "MESSAGE_SENT", "SPEND_REJECTED",
    "INBOX_FETCHED", "MESSAGE_FLAGGED", "FLAG_REVIEWED", "FLAG_DISMISSED", "TOKEN_FROZEN",
    "ACCESS_DENIED", "AUDIT_VIEWED", "ALERT",
}


def load_signing_key(path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("audit key must be Ed25519")
    return key


def roles_detail(roles) -> str:
    return "roles: " + ",".join(sorted(roles))


def _check_entry_fields(action: str, role: str, detail: str) -> None:
    if action not in ACTIONS:
        raise ValueError(f"unknown audit action: {action}")
    if not re.fullmatch(_ALLOWED_ROLE, role):
        raise ValueError(f"audit role not allowed: '{role}'")
    detail_is_allowed = False
    for pattern in _ALLOWED_DETAIL:
        if re.fullmatch(pattern, detail):
            detail_is_allowed = True
            break
    if not detail_is_allowed:
        raise ValueError(f"audit detail not allowed: '{detail}'")


class AuditLog:
    """Holds the Ed25519 signing key and appends signed, chained entries."""

    def __init__(self, signing_key: Ed25519PrivateKey):
        self._key = signing_key
        # Optional callback(audit, conn, action, detail), run after every
        # append inside the same transaction. The server sets it to the
        # alert engine; init-admin (no running server) leaves it unset.
        self.on_append = None

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def append_audit(self, conn: sqlite3.Connection, action: str, role: str, detail: str = "") -> int:
        """Append one entry. MUST be called inside db.write_transaction(conn).

        Being inside the caller's transaction is what makes auditing atomic:
        if the operation fails and rolls back, its audit entry disappears
        with it; if the audit insert fails, the operation is rolled back too.
        BEGIN IMMEDIATE also means no other writer can append between our
        "read the last entry" and "insert the next one", so the chain cannot fork.
        """
        if not conn.in_transaction:
            raise RuntimeError("append_audit must run inside write_transaction()")
        _check_entry_fields(action, role, detail)

        last = conn.execute(
            "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if last is None:
            # The very first entry: it links to the all-zeros "genesis" hash.
            seq = 1
            prev_hash = C.AUDIT_GENESIS_HASH
        else:
            seq = last["seq"] + 1
            prev_hash = last["entry_hash"]
        timestamp = db.now_iso()

        entry_hash = compute_entry_hash(seq, timestamp, action, role, detail, prev_hash)
        # Sign the raw 32-byte digest.
        signature = b64e(self._key.sign(bytes.fromhex(entry_hash)))

        # seq is the PRIMARY KEY: a second entry with the same seq (a fork)
        # is impossible even if the locking above were somehow bypassed.
        conn.execute(
            "INSERT INTO audit_log (seq, timestamp, action, role, detail, prev_hash, entry_hash, signature) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (seq, timestamp, action, role, detail, prev_hash, entry_hash, signature),
        )
        if self.on_append is not None:
            self.on_append(self, conn, action, detail)
        return seq
