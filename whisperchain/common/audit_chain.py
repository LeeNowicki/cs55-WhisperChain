"""Audit-log hash chain: shared by the server (which writes entries) and the
client (which verifies them independently).

Each entry's hash covers its own fields AND the previous entry's hash, so
changing, inserting, or removing any entry breaks every link after it.
Each hash is also signed with the server's Ed25519 key, so someone who edits
the database cannot simply recompute the hashes: they would need the key.
"""

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from whisperchain.common.constants import AUDIT_GENESIS_HASH
from whisperchain.common.encoding import b64d, canonical_json


_REQUIRED_FIELDS = {"seq", "timestamp", "action", "role", "detail", "prev_hash", "entry_hash", "signature"}


def compute_entry_hash(seq: int, timestamp: str, action: str, role: str, detail: str,
                       prev_hash: str) -> str:
    """sha256(canonical_json({seq, timestamp, action, role, detail, prev_hash})) as hex."""
    body = {
        "seq": seq,
        "timestamp": timestamp,
        "action": action,
        "role": role,
        "detail": detail,
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(canonical_json(body)).hexdigest()


def verify_chain(entries: list[dict], public_key: Ed25519PublicKey) -> tuple[int | None, str]:
    """Check a full log (entries in seq order).

    Returns (None, "ok") if everything checks out, otherwise
    (first bad seq, reason).
    """
    expected_prev = AUDIT_GENESIS_HASH
    for position, entry in enumerate(entries, start=1):
        # Entries come from the server, which we do not trust: a malformed
        # entry is a verification failure, not a crash.
        if not isinstance(entry, dict) or not _REQUIRED_FIELDS <= set(entry):
            return position, "entry is malformed"
        seq = entry["seq"]
        # 1. No gaps and no reordering: seq must be 1, 2, 3, ...
        if seq != position:
            return position, f"expected seq {position}, found {seq} (entry missing or reordered)"
        # 2. Linked to the previous entry.
        if entry["prev_hash"] != expected_prev:
            return seq, "prev_hash does not match the previous entry"
        # 3. The stored hash matches the stored fields.
        recomputed = compute_entry_hash(
            seq, entry["timestamp"], entry["action"], entry["role"], entry["detail"], entry["prev_hash"]
        )
        if recomputed != entry["entry_hash"]:
            return seq, "entry contents do not match its hash (entry was modified)"
        # 4. The server's key signed this hash.
        try:
            public_key.verify(b64d(entry["signature"]), bytes.fromhex(entry["entry_hash"]))
        except (InvalidSignature, ValueError):
            return seq, "signature is invalid"
        expected_prev = entry["entry_hash"]
    return None, "ok"
