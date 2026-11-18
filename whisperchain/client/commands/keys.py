"""keys sync / fingerprint / trust, and trust-on-first-use (TOFU) pinning.

The server hands out public keys, so a malicious server could swap a
recipient's key for its own and read their mail. Pinning defends against
that: the first fingerprint we see for a username is remembered, and any
later change is refused until the user compares fingerprints out of band
(in person, by phone, ...) and runs `keys trust`.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from whisperchain.client.api import ApiClient
from whisperchain.client.errors import ClientError
from whisperchain.client.store import ClientStore
from whisperchain.common import constants as C
from whisperchain.common.encoding import b64d
from whisperchain.common.fingerprint import fingerprint

STATUS_NEW = "new (pinned now)"
STATUS_OK = "ok"
STATUS_CHANGED = "CHANGED"
STATUS_INVALID = "invalid"


def load_checked_public_key(entry: dict, username: str):
    """Parse a directory entry's key and recompute its fingerprint ourselves.

    Returns the key object, or raises ClientError if the entry is
    inconsistent (we never trust the server-supplied fingerprint alone).
    """
    try:
        der = b64d(entry["public_key"])
        key = serialization.load_der_public_key(der)
    except (KeyError, ValueError):
        raise ClientError(f"directory entry for '{username}' is not a valid key") from None
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != C.USER_KEY_BITS:
        raise ClientError(f"directory entry for '{username}' is not an RSA-3072 key")
    if fingerprint(der) != entry.get("fingerprint"):
        raise ClientError(f"directory entry for '{username}' has a wrong fingerprint")
    return key


def _expected_fingerprint(store: ClientStore, pins: dict, username: str) -> str | None:
    """What we already trust for this user. For ourselves, that is the key we
    generated, so the server cannot advertise a different key for us."""
    identity = store.load_identity()
    if identity is not None and identity["username"] == username:
        return identity["fingerprint"]
    if username in pins:
        return pins[username]
    return None  # never seen this user before


def sync(store: ClientStore, api: ApiClient, include_moderators: bool) -> list[dict]:
    """Download the directory, compare against pins, and update the cache.

    Returns one result per user: {"list", "username", "fingerprint", "status"}.
    """
    sources = {"recipients": api.directory()["recipients"]}
    if include_moderators:
        sources["moderators"] = api.moderator_directory()["moderators"]

    pins = store.load_pins()
    cache = store.load_directory_cache()
    results = []
    for list_name, entries in sources.items():
        new_list = {}
        for entry in entries:
            username = entry.get("username")
            try:
                load_checked_public_key(entry, username)
            except ClientError:
                results.append({"list": list_name, "username": username, "fingerprint": "", "status": STATUS_INVALID})
                continue  # never cache an inconsistent entry

            fp = entry["fingerprint"]
            expected = _expected_fingerprint(store, pins, username)
            if expected is None:
                pins[username] = fp          # first sight: trust on first use
                status = STATUS_NEW
            elif expected == fp:
                status = STATUS_OK
            else:
                # Cache it (so `keys trust` can show it) but do NOT update the
                # pin: sending to this user is refused until trusted.
                status = STATUS_CHANGED
            new_list[username] = {"key_id": entry["key_id"], "public_key": entry["public_key"], "fingerprint": fp}
            results.append({"list": list_name, "username": username, "fingerprint": fp, "status": status})
        # Users missing from the new directory (revoked/deactivated) drop out
        # of the cache. Their pins stay, so a reappearing key is still checked.
        cache[list_name] = new_list

    store.save_pins(pins)
    store.save_directory_cache(cache)
    return results


def _cached_entry(store: ClientStore, username: str) -> dict | None:
    """The user's cached directory entry (recipient or moderator list), or None."""
    cache = store.load_directory_cache()
    for list_name in ("recipients", "moderators"):
        entries = cache.get(list_name, {})
        if username in entries:
            return entries[username]
    return None


def fingerprint_info(store: ClientStore, username: str | None = None) -> dict:
    """Own fingerprint (no username) or a cached user's, plus its pin status."""
    if username is None:
        identity = store.load_identity()
        if identity is None:
            raise ClientError("no identity in this config directory; register first")
        return {"username": identity["username"], "key_id": identity["key_id"],
                "fingerprint": identity["fingerprint"], "pinned": identity["fingerprint"]}
    entry = _cached_entry(store, username)
    if entry is None:
        raise ClientError(f"{username} is not in the local directory cache; run `keys sync`")
    return {"username": username, "key_id": entry["key_id"], "fingerprint": entry["fingerprint"],
            "pinned": _expected_fingerprint(store, store.load_pins(), username)}


def trust(store: ClientStore, username: str, confirm) -> bool:
    """Accept a changed key for `username`.

    `confirm(old_fp, new_fp)` must return True for the pin to change; the CLI
    shows both fingerprints and asks the user. Returns True if the pin changed.
    """
    identity = store.load_identity()
    if identity is not None and identity["username"] == username:
        raise ClientError("refusing to re-pin your own key; the server is advertising a key you did not create")
    entry = _cached_entry(store, username)
    if entry is None:
        raise ClientError(f"{username} is not in the local directory cache; run `keys sync`")
    load_checked_public_key(entry, username)
    pins = store.load_pins()
    old = pins.get(username)  # None if there was no pin
    if old == entry["fingerprint"]:
        return False  # nothing to do
    if not confirm(old, entry["fingerprint"]):
        return False
    pins[username] = entry["fingerprint"]
    store.save_pins(pins)
    return True


def trusted_key(store: ClientStore, username: str, list_name: str = "recipients"):
    """Return (entry, public_key) for `username`, or refuse if the cached key
    does not match the pin. Used before encrypting anything to a user."""
    cache = store.load_directory_cache()
    entries = cache.get(list_name, {})
    entry = entries.get(username)  # None if not in the list
    if entry is None:
        raise ClientError(f"{username} is not in the local directory; run `keys sync` "
                          "(they may not exist, be inactive, or not be a Recipient)")
    key = load_checked_public_key(entry, username)
    pinned = _expected_fingerprint(store, store.load_pins(), username)
    if pinned != entry["fingerprint"]:
        raise ClientError(
            f"the key for {username} does NOT match the pinned fingerprint; refusing. "
            f"Compare fingerprints with {username} out of band, then run `keys trust {username}`."
        )
    return entry, key
