"""Encoding helpers shared by client and server.

All binary values travel over JSON as URL-safe base64 strings.
Big integers (RSA n, e, signatures) are big-endian bytes, then base64.
"""

import base64
import binascii
import json


def b64e(data: bytes) -> str:
    """Encode bytes as a URL-safe base64 string."""
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Decode a URL-safe base64 string.

    validate=True makes the decoder reject stray characters instead of
    silently skipping them, so malformed input fails loudly.
    """
    if not isinstance(text, str):
        raise ValueError("expected a base64 string")
    try:
        return base64.b64decode(text.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("invalid base64") from exc


def int_to_bytes(value: int) -> bytes:
    """Big-endian bytes of a non-negative integer (at least one byte)."""
    if value < 0:
        raise ValueError("negative integers are not supported")
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def int_to_b64(value: int) -> str:
    return b64e(int_to_bytes(value))


def b64_to_int(text: str) -> int:
    return int.from_bytes(b64d(text), "big")


def canonical_json(obj) -> bytes:
    """Deterministic JSON bytes: sorted keys, no spaces, ASCII only.

    Used wherever we hash or sign JSON (the audit log), so the same data
    always produces exactly the same bytes on every machine.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
