"""send (anonymous) and inbox.

The send path NEVER uses the logged-in session: it builds the request from
the local token only and submits it through a fresh client with no
credentials (ApiClient.send_message). The inbox path is the opposite: it is
an authenticated, per-user operation.
"""

import secrets
import time

from whisperchain.client.api import ApiClient
from whisperchain.client.commands import keys
from whisperchain.client.display import sanitize
from whisperchain.client.errors import ApiError, ClientError, NetworkError
from whisperchain.client.store import ClientStore
from whisperchain.common import constants as C
from whisperchain.common.encoding import b64d, b64e
from whisperchain.common.envelope import EnvelopeError, build_envelope, decrypt_envelope

# Reject reasons after which the token can never be used again.
_TOKEN_DEAD = {"replay", "frozen", "closed_round", "bad_signature"}


def check_message_length(message: str) -> None:
    size = len(message.encode("utf-8"))
    if size > C.MAX_MESSAGE_BYTES:
        raise ClientError(f"message is {size} bytes; the maximum is {C.MAX_MESSAGE_BYTES}")


def random_delay(store: ClientStore) -> float:
    """Random wait before submitting. Without it, the server could match a
    TOKEN_ISSUED moment to the MESSAGE_SENT that follows right after."""
    config = store.load_config()
    low = float(config.get("send_delay_min", C.SEND_DELAY_MIN_SECONDS))
    high = float(config.get("send_delay_max", C.SEND_DELAY_MAX_SECONDS))
    return secrets.SystemRandom().uniform(low, max(low, high))


def _submit(store: ClientStore, api: ApiClient, body: dict) -> None:
    """Send the outbox body; clean up local state according to the answer."""
    try:
        api.send_message(body)
    except NetworkError:
        # Unknown whether it arrived: keep token and outbox for an identical resend.
        raise ClientError("could not reach the server; run `send` again to resubmit the same message") from None
    except ApiError as exc:
        if exc.reason == "bad_recipient":
            store.delete_outbox()  # token untouched; fix the directory and try again
            raise ClientError(f"{exc} Your token was NOT used.") from None
        if exc.reason in _TOKEN_DEAD:
            store.delete_token(body["round"])
            store.delete_outbox()
            raise
        if exc.status == 429:
            raise ClientError("the server is rate limiting sends; run `send` again later to resubmit") from None
        if exc.definitive:
            store.delete_outbox()  # malformed request: resending it would fail again
        raise
    # Delete the token only once the server has confirmed.
    store.delete_token(body["round"])
    store.delete_outbox()


def _wait(store: ClientStore, sleep, on_wait) -> None:
    delay = random_delay(store)
    if on_wait is not None:
        on_wait(delay)
    sleep(delay)


def send(store: ClientStore, api: ApiClient, to: str, message: str,
         now: bool = False, sleep=time.sleep, on_wait=None) -> dict:
    """on_wait(seconds) is called just before the random delay (CLI progress)."""
    pending = store.load_outbox()
    if pending is not None:
        # Finish the earlier, unconfirmed send before anything else, using the
        # exact same envelope (a new envelope would look like a replay).
        if not now:
            _wait(store, sleep, on_wait)
        _submit(store, api, pending)
        return {"status": "resubmitted", "recipient": pending["recipient"]}

    check_message_length(message)
    entry, public_key = keys.trusted_key(store, to)  # refuses on pin mismatch
    round_number = api.current_round()["round"]
    token = store.load_token(round_number)
    if token is None:
        raise ClientError(f"no token for round {round_number}; run `token request` first")

    envelope = build_envelope(message, public_key, entry["key_id"], round_number)
    body = {"recipient": to, "round": round_number, "envelope": b64e(envelope),
            "t": token["t"], "s": token["s"]}
    store.save_outbox(body)  # before the delay: a crash while waiting is recoverable

    if not now:
        _wait(store, sleep, on_wait)
    _submit(store, api, body)
    return {"status": "sent", "recipient": to}


# ---------------------------------------------------------------------------
# Inbox
# ---------------------------------------------------------------------------

def list_inbox(api: ApiClient) -> list[dict]:
    return api.inbox()["messages"]


def decrypt_message(entry: dict, private_key) -> tuple[str, bytes]:
    """(sanitized text, content key). Raises EnvelopeError if undecryptable."""
    text, content_key = decrypt_envelope(b64d(entry["envelope"]), private_key, entry["round"])
    # Strip control characters: a sender must not be able to inject terminal
    # escape sequences into the recipient's screen.
    return sanitize(text), content_key


def find_message(messages: list[dict], message_id: str) -> dict:
    for entry in messages:
        if entry["id"] == message_id:
            return entry
    raise ClientError("no such message in your inbox")


def read_message(store: ClientStore, api: ApiClient, message_id: str, passphrase: str) -> dict:
    """Decrypt one message in memory. Plaintext is never written to disk."""
    entry = find_message(list_inbox(api), message_id)
    private_key = store.load_private_key(passphrase)
    try:
        text, _content_key = decrypt_message(entry, private_key)
    except EnvelopeError as exc:
        return {"id": entry["id"], "round": entry["round"], "text": None, "error": str(exc)}
    return {"id": entry["id"], "round": entry["round"], "text": text, "error": None}
