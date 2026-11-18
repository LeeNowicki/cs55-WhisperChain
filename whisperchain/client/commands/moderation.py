"""flag (Recipient) and mod queue / review / freeze / dismiss (Moderator).

Flagging gives moderators the ability to read ONE message: the recipient's
client re-encrypts (wraps) that message's content key to each moderator's
public key. The server never sees the content key in the clear.
"""

from whisperchain.client.api import ApiClient
from whisperchain.client.commands import keys
from whisperchain.client.commands.messages import decrypt_message, find_message, list_inbox
from whisperchain.client.display import sanitize
from whisperchain.client.errors import ClientError
from whisperchain.client.store import ClientStore
from whisperchain.common import constants as C
from whisperchain.common.encoding import b64d, b64e
from whisperchain.common.envelope import EnvelopeError, decrypt_with_content_key, oaep, unwrap_content_key


def trusted_moderators(store: ClientStore, api: ApiClient) -> tuple[list, list[str]]:
    """Fetch moderator keys and keep only those matching our pins.

    Returns two lists:
      trusted: [{"username": ..., "key_id": ..., "public_key": ...}, ...]
      skipped: usernames whose key no longer matches our pin
    Wrapping to a changed key could hand the content key to an impostor
    chosen by the server, so those are skipped.
    """
    keys.sync(store, api, include_moderators=True)
    trusted = []
    skipped = []
    cache = store.load_directory_cache()
    moderator_entries = cache.get("moderators", {})
    for username in moderator_entries:
        try:
            entry, public_key = keys.trusted_key(store, username, list_name="moderators")
        except ClientError:
            skipped.append(username)
            continue
        trusted.append({"username": username, "key_id": entry["key_id"], "public_key": public_key})
    return trusted, skipped


def flag(store: ClientStore, api: ApiClient, message_id: str, passphrase: str,
         reason: str, confirm) -> dict:
    """Flag one of our messages. confirm(moderator_usernames, skipped) -> bool."""
    if len(reason) > C.FLAG_REASON_MAX_CHARS:
        raise ClientError(f"reason is limited to {C.FLAG_REASON_MAX_CHARS} characters")
    entry = find_message(list_inbox(api), message_id)
    private_key = store.load_private_key(passphrase)

    try:
        _text, content_key = decrypt_message(entry, private_key)
    except EnvelopeError:
        content_key = None  # undecryptable: flag it anyway, with nothing to share

    if content_key is None:
        # Nothing to share, so no moderator gets a copy.
        moderators = []
        skipped = []
    else:
        moderators, skipped = trusted_moderators(store, api)

    moderator_names = []
    for moderator in moderators:
        moderator_names.append(moderator["username"])
    if not confirm(moderator_names, skipped):
        raise ClientError("flag cancelled")

    # Encrypt ("wrap") the message's content key to each moderator's public
    # key: moderator key_id -> wrapped key (base64).
    wrapped = {}
    for moderator in moderators:
        wrapped_key = moderator["public_key"].encrypt(content_key, oaep())
        wrapped[moderator["key_id"]] = b64e(wrapped_key)

    result = api.flag_message(message_id, reason, wrapped)
    result["decryptable"] = (content_key is not None)
    return result


# ---------------------------------------------------------------------------
# Moderator side
# ---------------------------------------------------------------------------

def queue(api: ApiClient) -> list[dict]:
    return api.mod_queue()["flags"]


def review(store: ClientStore, api: ApiClient, flag_id: str, passphrase: str) -> dict:
    """Download a flagged message and decrypt it with OUR wrapped key copy."""
    flag_data = api.mod_review(flag_id)
    result = {"id": flag_data["id"], "round": flag_data["round"], "status": flag_data["status"],
              "reason": sanitize(flag_data["reason"]), "text": None}
    if flag_data["wrapped_key"] is None:
        result["note"] = "no content available (no key copy for you, or the recipient could not decrypt it)"
        return result

    private_key = store.load_private_key(passphrase)
    # Rebuild the envelope fields; the AAD comes from version, key_id and round.
    parts = {"version": flag_data["version"], "key_id": flag_data["key_id"],
             "wrapped_key": b64d(flag_data["wrapped_key"]),
             "nonce": b64d(flag_data["nonce"]), "ciphertext": b64d(flag_data["ciphertext"])}
    try:
        content_key = unwrap_content_key(parts, private_key)
        result["text"] = sanitize(decrypt_with_content_key(parts, content_key, flag_data["round"]))
    except EnvelopeError as exc:
        result["note"] = str(exc)
    return result


def freeze(api: ApiClient, flag_id: str) -> dict:
    return api.mod_freeze(flag_id)


def dismiss(api: ApiClient, flag_id: str) -> dict:
    return api.mod_dismiss(flag_id)
