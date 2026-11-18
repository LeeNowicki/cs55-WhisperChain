"""Passwords (argon2), account-input validation, JWT sessions, and the
require(permission) check used by every non-public route.
"""

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request

from whisperchain.common import constants as C
from whisperchain.server import db
from whisperchain.server.permissions import ALL_PERMISSIONS, role_granting

# argon2id with the library's recommended parameters: deliberately slow and
# memory-hard so stolen hashes are expensive to brute-force.
_hasher = PasswordHasher()

# Hash of a random password nobody knows. Login verifies against it when the
# username does not exist, so "unknown user" takes as long as "wrong
# password" and the response time does not reveal which usernames exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """True if the password matches. Never raises on a wrong password."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def dummy_verify(password: str) -> None:
    """Spend the same argon2 effort as a real check, then throw it away."""
    verify_password(_DUMMY_HASH, password)


def validate_username(username: str) -> None:
    if not isinstance(username, str) or not re.fullmatch(C.USERNAME_PATTERN, username):
        raise ValueError(
            "username must be 3-32 characters: letters, digits, '_', '.', '-'"
        )


def validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < C.MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {C.MIN_PASSWORD_LENGTH} characters")
    if len(password) > C.MAX_PASSWORD_LENGTH:
        raise ValueError("password is too long")


# ---------------------------------------------------------------------------
# JWT sessions
# ---------------------------------------------------------------------------

def create_session_token(user_id: int, secret: bytes, lifetime_minutes: int) -> str:
    """Signed session token carrying ONLY the user id.

    Roles are deliberately not in the token: they are re-read from the
    database on every request, so a role change or deactivation takes effect
    immediately instead of when the token expires.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=lifetime_minutes),
    }
    return jwt.encode(payload, secret, algorithm=C.JWT_ALGORITHM)


def decode_session_token(token: str, secret: bytes) -> int:
    """Return the user id, or raise jwt.InvalidTokenError.

    algorithms is pinned to HS256 so an attacker cannot pick a different
    algorithm (for example "none") in the token header. "exp" is required so
    a token without an expiry is rejected rather than living forever.
    A small leeway absorbs clock adjustments (see JWT_CLOCK_SKEW_SECONDS).
    """
    payload = jwt.decode(
        token,
        secret,
        algorithms=[C.JWT_ALGORITHM],
        options={"require": ["exp", "iat", "sub"]},
        leeway=C.JWT_CLOCK_SKEW_SECONDS,
    )
    try:
        return int(payload["sub"])
    except (TypeError, ValueError):
        raise jwt.InvalidTokenError("bad subject") from None


# ---------------------------------------------------------------------------
# Per-request authentication and authorization
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CurrentUser:
    id: int
    username: str
    roles: frozenset
    # The role that granted the permission for this request. Audit entries
    # record this role, never the user's id or name.
    acting_role: str


def load_roles(conn, user_id: int) -> frozenset:
    rows = conn.execute("SELECT role FROM user_roles WHERE user_id = ?", (user_id,))
    roles = set()
    for row in rows:
        roles.add(row["role"])
    # frozenset = a set that cannot be changed afterwards.
    return frozenset(roles)


def _not_authenticated() -> HTTPException:
    # 401 = "we don't know who you are". Never audit-logged: anyone on the
    # internet can cause these, and logging them would only add noise.
    return HTTPException(
        status_code=401,
        detail="not logged in or session expired",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require(permission: str):
    """Build a FastAPI dependency that lets the request through only if the
    logged-in user currently holds `permission`.

    Use as:  user: CurrentUser = Depends(require("invite:create"))
    """
    # Catch typos when the app is built, not when a user hits the route.
    if permission not in ALL_PERMISSIONS:
        raise ValueError(f"unknown permission: {permission}")

    def dependency(request: Request, conn=Depends(db.get_db)) -> CurrentUser:
        # 1. Authenticate: a valid, unexpired JWT signed with our secret.
        #    The header looks like:  Authorization: Bearer <token>
        header = request.headers.get("Authorization", "")
        parts = header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or parts[1] == "":
            raise _not_authenticated()
        token = parts[1]
        try:
            user_id = decode_session_token(token, request.app.state.jwt_secret)
        except jwt.InvalidTokenError:
            raise _not_authenticated() from None

        # 2. Load the user and roles FROM THE DATABASE on every request, so
        #    deactivation and role changes take effect immediately, not when
        #    the 45-minute token expires.
        row = conn.execute(
            "SELECT id, username, active FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row is None or not row["active"]:
            raise _not_authenticated()
        roles = load_roles(conn, user_id)

        # 3. Authorize: is the permission in the union of the user's roles?
        acting_role = role_granting(roles, permission)
        if acting_role is None:
            # 403 = "we know who you are, and you may not do this". Record the
            # attempt by role list and permission only (no user id or name).
            if len(roles) > 0:
                role_list = ",".join(sorted(roles))
            else:
                role_list = "none"
            with db.write_transaction(conn):
                request.app.state.audit.append_audit(
                    conn, "ACCESS_DENIED", role_list, f"permission: {permission}"
                )
            raise HTTPException(status_code=403, detail="you do not have permission for this action")
        return CurrentUser(id=row["id"], username=row["username"], roles=roles,
                           acting_role=acting_role)

    # Attach the permission so the default-deny test can find it on each route.
    dependency.permission = permission
    return dependency
