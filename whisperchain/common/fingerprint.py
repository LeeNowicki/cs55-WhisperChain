"""Public-key fingerprints for out-of-band comparison."""

import hashlib

from cryptography.hazmat.primitives import serialization


def public_key_der(public_key) -> bytes:
    """Standard SubjectPublicKeyInfo (SPKI) DER encoding of a public key."""
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def fingerprint(spki_der: bytes) -> str:
    """SHA-256 of the SPKI DER bytes, 64 lowercase hex characters."""
    return hashlib.sha256(spki_der).hexdigest()


def format_fingerprint(fp: str) -> str:
    """Display form: 8 groups of 8 hex chars, easier to read aloud."""
    groups = []
    # range(0, 64, 8) gives 0, 8, 16, ... 56: the start of each group.
    for start in range(0, len(fp), 8):
        groups.append(fp[start:start + 8])
    return " ".join(groups)
