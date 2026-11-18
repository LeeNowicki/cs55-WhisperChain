"""Public account routes: proof-of-possession challenge, register, login."""

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
import uuid

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from whisperchain.common import constants as C
from whisperchain.common.encoding import b64d, b64e
from whisperchain.common.fingerprint import fingerprint, public_key_der
from whisperchain.server import auth, db
from whisperchain.server.audit import roles_detail
from whisperchain.server.invites import find_usable_invite
from whisperchain.server.ratelimit import rate_limited

router = APIRouter()

# Base64 of a 1024-byte DER key is at most 1368 characters.
_MAX_KEY_B64 = 1400

INVALID_INVITE = "invalid, used, or expired invite code"
INVALID_LOGIN = "invalid username or password"


# ---------------------------------------------------------------------------
# Request models. extra="forbid" rejects unknown fields, so in particular a
# client cannot smuggle in a "roles" field: roles come only from the invite.
# ---------------------------------------------------------------------------

class ChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_key: str = Field(max_length=_MAX_KEY_B64)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    invite_code: str = Field(max_length=100)
    username: str = Field(max_length=64)
    password: str = Field(max_length=C.MAX_PASSWORD_LENGTH)
    public_key: str = Field(max_length=_MAX_KEY_B64)
    challenge_id: str = Field(max_length=100)
    challenge_response: str = Field(max_length=100)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(max_length=64)
    password: str = Field(max_length=C.MAX_PASSWORD_LENGTH)


# ---------------------------------------------------------------------------
# Public key validation
# ---------------------------------------------------------------------------

def validate_user_public_key(public_key_b64: str) -> tuple[bytes, rsa.RSAPublicKey]:
    """Parse and strictly check a user's public key. Raise ValueError if bad.

    The server parses the key itself and never trusts client-supplied
    metadata (size, fingerprint, ...).
    """
    der = b64d(public_key_b64)
    if len(der) > C.MAX_PUBLIC_KEY_DER_BYTES:
        raise ValueError("public key is too large")
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, UnsupportedAlgorithm):
        raise ValueError("public key could not be parsed") from None
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("public key must be RSA")
    if key.key_size != C.USER_KEY_BITS:
        raise ValueError(f"public key must be exactly {C.USER_KEY_BITS} bits")
    if key.public_numbers().e != C.RSA_PUBLIC_EXPONENT:
        raise ValueError("public key exponent must be 65537")
    # Re-encoding must give back exactly the submitted bytes. This rejects
    # odd-but-parseable encodings, so one key has exactly one fingerprint.
    if public_key_der(key) != der:
        raise ValueError("public key is not in canonical SPKI DER form")
    return der, key


# ---------------------------------------------------------------------------
# Proof-of-possession challenges (in memory, 5-minute TTL, one-time use)
# ---------------------------------------------------------------------------

class ChallengeStore:
    """Remembers outstanding challenges.

    We keep only SHA-256(challenge), never the challenge itself, plus the
    fingerprint of the key it was encrypted to.
    """

    MAX_OUTSTANDING = 10_000  # bound memory if someone floods the endpoint

    def __init__(self, ttl_seconds: int = C.CHALLENGE_TTL_SECONDS):
        self.ttl = ttl_seconds
        # challenge_id -> {"hash": ..., "fingerprint": ..., "expires": ...}
        self._entries = {}
        self._lock = threading.Lock()

    def _purge_expired(self, now: float) -> None:
        # First collect the expired ids, then delete them (a dict must not be
        # changed while we are looping over it).
        expired_ids = []
        for challenge_id in self._entries:
            if self._entries[challenge_id]["expires"] <= now:
                expired_ids.append(challenge_id)
        for challenge_id in expired_ids:
            del self._entries[challenge_id]

    def add(self, challenge: bytes, key_fingerprint: str) -> str:
        now = time.monotonic()
        challenge_id = secrets.token_urlsafe(16)
        with self._lock:
            self._purge_expired(now)
            if len(self._entries) >= self.MAX_OUTSTANDING:
                raise HTTPException(status_code=503, detail="server busy; try again later")
            self._entries[challenge_id] = {
                "hash": hashlib.sha256(challenge).digest(),
                "fingerprint": key_fingerprint,
                "expires": now + self.ttl,
            }
        return challenge_id

    def consume(self, challenge_id: str, response: bytes, key_fingerprint: str) -> bool:
        """Check a response. The challenge is removed whatever the outcome,
        so each challenge can be tried exactly once."""
        now = time.monotonic()
        with self._lock:
            if challenge_id not in self._entries:
                return False
            entry = self._entries[challenge_id]
            del self._entries[challenge_id]  # one try only
        if entry["expires"] <= now:
            return False
        if entry["fingerprint"] != key_fingerprint:
            return False
        # Constant-time comparison: timing does not reveal how close a guess was.
        response_hash = hashlib.sha256(response).digest()
        return hmac.compare_digest(response_hash, entry["hash"])


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    )


@router.post("/register/challenge", dependencies=[Depends(rate_limited("register"))])
def register_challenge(body: ChallengeRequest, request: Request):
    """Encrypt 32 random bytes to the submitted key.

    Only someone holding the matching private key can decrypt and return them,
    which proves the registrant really owns the key they are registering.
    """
    try:
        der, key = validate_user_public_key(body.public_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    challenge = secrets.token_bytes(C.CHALLENGE_BYTES)
    encrypted = key.encrypt(challenge, _oaep())
    challenge_id = request.app.state.challenges.add(challenge, fingerprint(der))
    return {"challenge_id": challenge_id, "encrypted_challenge": b64e(encrypted)}


@router.post("/register", dependencies=[Depends(rate_limited("register"))])
def register(body: RegisterRequest, request: Request, conn=Depends(db.get_db)):
    # --- Step 1: validate EVERYTHING before writing anything. ---------------
    # A bad key or bad password must never burn the invite.
    try:
        auth.validate_username(body.username)
        auth.validate_password(body.password)
        der, _key = validate_user_public_key(body.public_key)
        response_bytes = b64d(body.challenge_response)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    key_fp = fingerprint(der)
    if not request.app.state.challenges.consume(body.challenge_id, response_bytes, key_fp):
        raise HTTPException(status_code=400, detail="proof of key possession failed")

    if find_usable_invite(conn, body.invite_code) is None:
        raise HTTPException(status_code=400, detail=INVALID_INVITE)

    # argon2 is slow, so hash before taking the database write lock.
    password_hash = auth.hash_password(body.password)
    key_id = str(uuid.uuid4())

    # --- Step 2: one transaction: consume invite, create user, roles, key. ---
    try:
        with db.write_transaction(conn):
            # Re-check inside the lock: another request may have used the
            # invite between our first check and now.
            invite = find_usable_invite(conn, body.invite_code)
            if invite is None:
                raise HTTPException(status_code=400, detail=INVALID_INVITE)
            conn.execute("UPDATE invites SET used = 1 WHERE id = ?", (invite["id"],))

            now = db.now_iso()
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, active, created_at) "
                "VALUES (?, ?, 1, ?)",
                (body.username, password_hash, now),
            )
            user_id = cur.lastrowid
            # Roles come ONLY from the invite, never from the request.
            roles = json.loads(invite["roles"])
            for role in roles:
                conn.execute(
                    "INSERT INTO user_roles (user_id, role) VALUES (?, ?)", (user_id, role)
                )
            conn.execute(
                "INSERT INTO public_keys (key_id, user_id, public_key, fingerprint, status, created_at) "
                "VALUES (?, ?, ?, ?, 'active', ?)",
                (key_id, user_id, der, key_fp, now),
            )
            # Audited inside the same transaction: both entries exist if and
            # only if the account exists. Roles only, never the username.
            audit = request.app.state.audit
            audit.append_audit(conn, "USER_REGISTERED", "System", roles_detail(roles))
            audit.append_audit(conn, "KEY_REGISTERED", "System")
            if C.ROLE_MODERATOR in roles:
                request.app.state.alerts.moderator_granted(audit, conn)
    except sqlite3.IntegrityError:
        # UNIQUE(username) failed; the rollback also un-used the invite.
        raise HTTPException(status_code=409, detail="that username is already taken")

    return {"username": body.username, "roles": roles, "key_id": key_id, "fingerprint": key_fp}


@router.post("/login", dependencies=[Depends(rate_limited("login"))])
def login(body: LoginRequest, request: Request, conn=Depends(db.get_db)):
    row = conn.execute(
        "SELECT id, password_hash, active FROM users WHERE username = ?", (body.username,)
    ).fetchone()
    if row is None:
        # Same work and same message as a wrong password, so attackers cannot
        # use login to discover which usernames exist.
        auth.dummy_verify(body.password)
        raise HTTPException(status_code=401, detail=INVALID_LOGIN)
    password_ok = auth.verify_password(row["password_hash"], body.password)
    if not password_ok or not row["active"]:
        raise HTTPException(status_code=401, detail=INVALID_LOGIN)

    roles = sorted(auth.load_roles(conn, row["id"]))
    token = auth.create_session_token(
        row["id"], request.app.state.jwt_secret, request.app.state.config["jwt_lifetime_minutes"]
    )
    return {"token": token, "roles": roles}
