"""Public-key directory routes.

The directory lists only ACTIVE keys of ACTIVE users holding the relevant
role. Clients never trust the server's word alone: they recompute each
fingerprint and compare it with their trust-on-first-use pins.
"""

from fastapi import APIRouter, Depends

from whisperchain.common import constants as C
from whisperchain.common.encoding import b64e
from whisperchain.server import db
from whisperchain.server.auth import CurrentUser, require

router = APIRouter()


def _keys_for_role(conn, role: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT u.username, k.key_id, k.public_key, k.fingerprint
        FROM public_keys k
        JOIN users u ON u.id = k.user_id
        JOIN user_roles r ON r.user_id = u.id
        WHERE r.role = ? AND u.active = 1 AND k.status = 'active'
        ORDER BY u.username
        """,
        (role,),
    ).fetchall()
    entries = []
    for row in rows:
        entries.append({
            "username": row["username"],
            "key_id": row["key_id"],
            "public_key": b64e(row["public_key"]),
            "fingerprint": row["fingerprint"],
        })
    return entries


@router.get("/directory")
def directory(user: CurrentUser = Depends(require("directory:read")), conn=Depends(db.get_db)):
    """Everyone who can currently receive messages."""
    return {"recipients": _keys_for_role(conn, C.ROLE_RECIPIENT)}


@router.get("/directory/moderators")
def moderator_directory(
    user: CurrentUser = Depends(require("moderator_keys:read")), conn=Depends(db.get_db)
):
    """Moderator keys, so a Recipient can wrap a flagged message's content key to them."""
    return {"moderators": _keys_for_role(conn, C.ROLE_MODERATOR)}
