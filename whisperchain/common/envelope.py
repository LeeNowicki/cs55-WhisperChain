"""Message envelope: hybrid encryption with a fixed total size.

    version (1) | key_id (16) | wrapped_key (384) | nonce (12) | ciphertext+tag (1040)

- A fresh random AES-256 content key encrypts the message (AES-GCM gives
  confidentiality AND integrity: any change is detected).
- The content key is wrapped with the recipient's RSA-OAEP public key, so
  only the recipient's private key can recover it.
- The message is padded to 1024 bytes, so every envelope is exactly 1453
  bytes and its size reveals nothing about the message length.
- The AAD (authenticated but not encrypted) binds the ciphertext to its
  version, key_id and round: moving it to another round or key fails.
- No sender name, timestamp, or signature is inside: the envelope says
  nothing about who sent it.
"""

import secrets
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from whisperchain.common import constants as C

DECRYPT_FAILED = "message could not be decrypted"


class EnvelopeError(ValueError):
    """Malformed envelope, or decryption failed. Messages are deliberately vague."""


def oaep() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------

def pad(message: str) -> bytes:
    """2-byte big-endian length, the UTF-8 message, then zeros up to 1024 bytes."""
    data = message.encode("utf-8")
    if len(data) > C.MAX_MESSAGE_BYTES:
        raise EnvelopeError(f"message is too long ({len(data)} bytes; max {C.MAX_MESSAGE_BYTES})")
    block = len(data).to_bytes(C.LENGTH_PREFIX_BYTES, "big") + data
    return block + b"\x00" * (C.PLAINTEXT_BLOCK_BYTES - len(block))


def unpad(block: bytes) -> str:
    length = int.from_bytes(block[: C.LENGTH_PREFIX_BYTES], "big")
    if len(block) != C.PLAINTEXT_BLOCK_BYTES or length > C.MAX_MESSAGE_BYTES:
        raise EnvelopeError(DECRYPT_FAILED)
    end = C.LENGTH_PREFIX_BYTES + length
    # Every padding byte after the message must be zero.
    for padding_byte in block[end:]:
        if padding_byte != 0:
            raise EnvelopeError(DECRYPT_FAILED)
    try:
        return block[C.LENGTH_PREFIX_BYTES:end].decode("utf-8")
    except UnicodeDecodeError:
        raise EnvelopeError(DECRYPT_FAILED) from None


# ---------------------------------------------------------------------------
# Header and AAD
# ---------------------------------------------------------------------------

def aad(version: int, key_id: str, round_number: int) -> bytes:
    """version byte || key_id (16 raw bytes) || round (4 bytes big-endian)."""
    return bytes([version]) + uuid.UUID(key_id).bytes + round_number.to_bytes(4, "big")


def parse_header(envelope: bytes) -> dict:
    """Split an envelope into its fields, rejecting anything malformed."""
    if not isinstance(envelope, (bytes, bytearray)) or len(envelope) != C.ENVELOPE_BYTES:
        raise EnvelopeError("envelope has the wrong length")
    version = envelope[0]
    if version != C.ENVELOPE_VERSION:
        raise EnvelopeError("unknown envelope version")
    pos = C.VERSION_BYTES
    key_id_bytes = envelope[pos : pos + C.KEY_ID_BYTES]
    pos += C.KEY_ID_BYTES
    key_id = uuid.UUID(bytes=bytes(key_id_bytes))
    # Our key ids are random (version 4) UUIDs; anything else is malformed.
    if key_id.version != 4 or key_id.variant != uuid.RFC_4122:
        raise EnvelopeError("malformed key id")
    wrapped = envelope[pos : pos + C.WRAPPED_KEY_BYTES]
    pos += C.WRAPPED_KEY_BYTES
    nonce = envelope[pos : pos + C.NONCE_BYTES]
    pos += C.NONCE_BYTES
    ciphertext = envelope[pos:]
    return {"version": version, "key_id": str(key_id), "wrapped_key": bytes(wrapped),
            "nonce": bytes(nonce), "ciphertext": bytes(ciphertext)}


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------

def build_envelope(message: str, recipient_public_key, key_id: str, round_number: int) -> bytes:
    plaintext = pad(message)
    content_key = secrets.token_bytes(C.CONTENT_KEY_BYTES)
    nonce = secrets.token_bytes(C.NONCE_BYTES)  # random; a key is never reused anyway
    wrapped = recipient_public_key.encrypt(content_key, oaep())
    ciphertext = AESGCM(content_key).encrypt(nonce, plaintext, aad(C.ENVELOPE_VERSION, key_id, round_number))
    envelope = bytes([C.ENVELOPE_VERSION]) + uuid.UUID(key_id).bytes + wrapped + nonce + ciphertext
    assert len(envelope) == C.ENVELOPE_BYTES
    return envelope


def decrypt_with_content_key(parts: dict, content_key: bytes, round_number: int) -> str:
    """Decrypt given the already-unwrapped content key (used by moderators)."""
    try:
        plaintext = AESGCM(content_key).decrypt(
            parts["nonce"], parts["ciphertext"], aad(parts["version"], parts["key_id"], round_number)
        )
    except (InvalidTag, ValueError):
        # One uniform error, no partial output: never reveal WHY it failed.
        raise EnvelopeError(DECRYPT_FAILED) from None
    return unpad(plaintext)


def unwrap_content_key(parts: dict, private_key) -> bytes:
    try:
        content_key = private_key.decrypt(parts["wrapped_key"], oaep())
    except ValueError:
        raise EnvelopeError(DECRYPT_FAILED) from None
    if len(content_key) != C.CONTENT_KEY_BYTES:
        raise EnvelopeError(DECRYPT_FAILED)
    return content_key


def decrypt_envelope(envelope: bytes, private_key, round_number: int) -> tuple[str, bytes]:
    """Return (message, content_key). The content key is returned so the
    recipient can later wrap it to moderators when flagging."""
    try:
        parts = parse_header(envelope)
    except EnvelopeError:
        raise EnvelopeError(DECRYPT_FAILED) from None
    content_key = unwrap_content_key(parts, private_key)
    return decrypt_with_content_key(parts, content_key, round_number), content_key
