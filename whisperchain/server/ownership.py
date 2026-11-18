"""Per-object ownership checks.

Role permissions say WHAT KIND of action a user may take ("read an inbox");
ownership says WHICH objects ("only your own inbox"). Queries are always
scoped by the session user's id, never by an id taken from the request.
"""

from fastapi import HTTPException


def get_owned_message(conn, message_id: str, user_id: int):
    """Return the message row if it belongs to user_id, else 404.

    404 (not 403) for other people's messages: a 403 would confirm that the
    message id exists, which leaks information.
    """
    row = conn.execute(
        "SELECT * FROM messages WHERE id = ? AND recipient_id = ?", (message_id, user_id)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="message not found")
    return row
