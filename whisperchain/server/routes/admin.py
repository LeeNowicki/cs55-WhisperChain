"""Admin routes: invites and user management.

Admins manage accounts but can never see message content, token data, or
who sent what. They also cannot create or remove Admins (host-only via
`init-admin`) and cannot upload or replace anyone's key.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from whisperchain.common import constants as C
from whisperchain.server import auth, db, rounds
from whisperchain.server.audit import roles_detail
from whisperchain.server.auth import CurrentUser, require
from whisperchain.server.invites import create_invite

router = APIRouter(prefix="/admin")


class RolesBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    roles: list[str] = Field(min_length=1, max_length=len(C.ALL_ROLES))


def _check_invitable(roles: list[str]) -> list[str]:
    """Only Sender / Recipient / Moderator may be handed out over the network."""
    for role in roles:
        if role not in C.INVITABLE_ROLES:
            raise HTTPException(status_code=400, detail=f"role not allowed: {role}")
    return sorted(set(roles))


def _get_target_user(conn, user_id: int):
    row = conn.execute("SELECT id, active FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="user not found")
    return row


def _refuse_if_admin(conn, user_id: int) -> None:
    # Admin accounts are managed only on the server host; an Admin token
    # cannot demote, re-role, or deactivate an Admin.
    if C.ROLE_ADMIN in auth.load_roles(conn, user_id):
        raise HTTPException(status_code=400, detail="Admin accounts can only be managed on the server host")


@router.post("/invites")
def create_invite_route(
    body: RolesBody,
    request: Request,
    user: CurrentUser = Depends(require("invite:create")),
    conn=Depends(db.get_db),
):
    roles = _check_invitable(body.roles)
    with db.write_transaction(conn):
        code, expires_at = create_invite(conn, roles, request.app.state.config["invite_expiry_days"])
        request.app.state.audit.append_audit(conn, "INVITE_CREATED", user.acting_role, roles_detail(roles))
    # The plain code is returned exactly once; the server keeps only its hash.
    return {"invite_code": code, "roles": roles, "expires_at": expires_at}


@router.get("/users")
def list_users(user: CurrentUser = Depends(require("user:list")), conn=Depends(db.get_db)):
    # Only id, username, roles, and active flag: no password hashes, no keys,
    # nothing about messages or tokens.
    users = []
    for row in conn.execute("SELECT id, username, active FROM users ORDER BY id"):
        users.append({
            "id": row["id"],
            "username": row["username"],
            "roles": sorted(auth.load_roles(conn, row["id"])),
            "active": bool(row["active"]),
        })
    return {"users": users}


@router.post("/users/{user_id}/roles")
def set_roles(
    user_id: int,
    body: RolesBody,
    request: Request,
    user: CurrentUser = Depends(require("user:set_roles")),
    conn=Depends(db.get_db),
):
    roles = _check_invitable(body.roles)  # Admin can never be granted
    with db.write_transaction(conn):
        _get_target_user(conn, user_id)
        _refuse_if_admin(conn, user_id)    # Admin can never be removed
        had_moderator = C.ROLE_MODERATOR in auth.load_roles(conn, user_id)
        # Replace the whole role set in one transaction.
        conn.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
        for role in roles:
            conn.execute("INSERT INTO user_roles (user_id, role) VALUES (?, ?)", (user_id, role))
        # Logs the new role set only, never whose roles changed.
        audit = request.app.state.audit
        audit.append_audit(conn, "ROLES_CHANGED", user.acting_role, roles_detail(roles))
        if C.ROLE_MODERATOR in roles and not had_moderator:
            # Moderators can read flagged content: every new one is alerted.
            request.app.state.alerts.moderator_granted(audit, conn)
    return {"id": user_id, "roles": roles}


@router.post("/users/{user_id}/deactivate")
def deactivate_user(
    user_id: int,
    request: Request,
    user: CurrentUser = Depends(require("user:deactivate")),
    conn=Depends(db.get_db),
):
    with db.write_transaction(conn):
        _get_target_user(conn, user_id)
        _refuse_if_admin(conn, user_id)
        conn.execute("UPDATE users SET active = 0 WHERE id = ?", (user_id,))
        request.app.state.audit.append_audit(conn, "USER_DEACTIVATED", user.acting_role)
    # Takes effect on the user's very next request: require() re-reads
    # `active` from the database every time.
    return {"id": user_id, "active": False}


@router.post("/keys/{key_id}/revoke")
def revoke_key(
    key_id: str,
    request: Request,
    user: CurrentUser = Depends(require("key:revoke")),
    conn=Depends(db.get_db),
):
    """Mark a key revoked. It disappears from the directory at once, and
    messages addressed to it will be refused.

    There is deliberately NO route for an Admin to upload or replace a key:
    an Admin who could swap a user's key could read that user's mail.
    """
    with db.write_transaction(conn):
        row = conn.execute("SELECT status FROM public_keys WHERE key_id = ?", (key_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="key not found")
        if row["status"] == "revoked":
            raise HTTPException(status_code=409, detail="key is already revoked")
        conn.execute("UPDATE public_keys SET status = 'revoked' WHERE key_id = ?", (key_id,))
        request.app.state.audit.append_audit(conn, "KEY_REVOKED", user.acting_role)
    return {"key_id": key_id, "status": "revoked"}


@router.post("/rounds/start")
def start_round(
    request: Request,
    user: CurrentUser = Depends(require("round:start")),
    conn=Depends(db.get_db),
):
    """Close the current round (its tokens stop working) and open a new one
    with a brand-new token-signing key."""
    private_key = rounds.generate_round_key()  # slow: do it before locking the DB
    with db.write_transaction(conn):
        round_number = rounds.start_new_round(conn, request.app.state.paths, private_key)
        request.app.state.audit.append_audit(conn, "ROUND_STARTED", user.acting_role, f"round: {round_number}")
    return {"round": round_number}
