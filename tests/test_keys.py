"""Stage 5: directory, fingerprints, TOFU pinning, key revocation."""

import pytest

from conftest import always_no, always_yes, api_client, auth_header
from whisperchain.client.commands import keys
from whisperchain.client.errors import ClientError
from whisperchain.client.store import ClientStore
from whisperchain.common.encoding import b64d
from whisperchain.common.fingerprint import fingerprint, format_fingerprint, public_key_der
from whisperchain.server import db
from whisperchain.server.permissions import list_api_routes


@pytest.fixture
def w(fresh_world):
    return fresh_world


def api(world, who):
    return api_client(world["app"], world["tokens"][who])


def directory_usernames(world, who, path, list_name):
    """Usernames listed by a directory route, as seen by `who`."""
    response = world["client"].get(path, headers=auth_header(world["tokens"][who]))
    names = []
    for entry in response.json()[list_name]:
        names.append(entry["username"])
    return names


def status_by_username(results) -> dict:
    """Turn keys.sync() results into {username: status}."""
    statuses = {}
    for result in results:
        statuses[result["username"]] = result["status"]
    return statuses


# ---------------------------------------------------------------------------
# Server: who is listed
# ---------------------------------------------------------------------------

def test_directory_lists_only_active_recipient_keys(w):
    # recipient and both hold Recipient; sender/moderator/victim/root do not.
    assert directory_usernames(w, "sender", "/directory", "recipients") == ["both", "recipient"]

    # Deactivated users drop out.
    w["client"].post(f"/admin/users/{w['ids']['both']}/deactivate", headers=auth_header(w["tokens"]["admin"]))
    assert directory_usernames(w, "sender", "/directory", "recipients") == ["recipient"]


def test_moderator_directory(w):
    assert directory_usernames(w, "recipient", "/directory/moderators", "moderators") == ["moderator"]


def test_directory_entries_are_well_formed(w):
    response = w["client"].get("/directory", headers=auth_header(w["tokens"]["sender"]))
    for entry in response.json()["recipients"]:
        assert sorted(entry) == ["fingerprint", "key_id", "public_key", "username"]
        assert fingerprint(b64d(entry["public_key"])) == entry["fingerprint"]


def test_revoked_key_disappears(w):
    client = w["client"]
    admin = auth_header(w["tokens"]["admin"])
    key_id = w["ids"]["recipient_key"]
    assert client.post(f"/admin/keys/{key_id}/revoke", headers=admin).status_code == 200
    assert "recipient" not in directory_usernames(w, "sender", "/directory", "recipients")
    # Revoking again, or an unknown key, is refused.
    assert client.post(f"/admin/keys/{key_id}/revoke", headers=admin).status_code == 409
    assert client.post("/admin/keys/no-such-key/revoke", headers=admin).status_code == 404

    conn = db.connect(w["paths"].db)
    last = conn.execute("SELECT action, role, detail FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    conn.close()
    assert last["action"] == "KEY_REVOKED"
    assert last["role"] == "Admin"
    assert last["detail"] == ""


def test_no_route_lets_admin_upload_a_key(w):
    for path, route in list_api_routes(w["app"].routes):
        if path.startswith("/admin/keys"):
            assert path.endswith("/revoke")


# ---------------------------------------------------------------------------
# Client: TOFU pinning
# ---------------------------------------------------------------------------

def test_sync_pins_on_first_use(w, tmp_path):
    store = ClientStore(tmp_path / "s")
    results = keys.sync(store, api(w, "sender"), include_moderators=False)
    assert status_by_username(results) == {"both": keys.STATUS_NEW, "recipient": keys.STATUS_NEW}
    assert sorted(store.load_pins()) == ["both", "recipient"]

    # Second sync: nothing changed.
    results = keys.sync(store, api(w, "sender"), include_moderators=False)
    for result in results:
        assert result["status"] == keys.STATUS_OK


def test_sync_includes_moderators_for_recipients(w, tmp_path):
    store = ClientStore(tmp_path / "r")
    keys.sync(store, api(w, "recipient"), include_moderators=True)
    assert list(store.load_directory_cache()["moderators"]) == ["moderator"]


def swap_key_in_db(world, username, new_private_key):
    """Simulate a malicious/compromised server replacing a user's key."""
    der = public_key_der(new_private_key.public_key())
    conn = db.connect(world["paths"].db)
    conn.execute(
        "UPDATE public_keys SET public_key = ?, fingerprint = ? "
        "WHERE user_id = (SELECT id FROM users WHERE username = ?)",
        (der, fingerprint(der), username))
    conn.close()


def test_pin_mismatch_blocks(w, tmp_path, user_keys):
    store = ClientStore(tmp_path / "s")
    keys.sync(store, api(w, "sender"), include_moderators=False)
    keys.trusted_key(store, "recipient")  # fine before the swap

    swap_key_in_db(w, "recipient", user_keys[5])
    results = keys.sync(store, api(w, "sender"), include_moderators=False)
    assert status_by_username(results)["recipient"] == keys.STATUS_CHANGED

    with pytest.raises(ClientError, match="does NOT match"):
        keys.trusted_key(store, "recipient")
    keys.trusted_key(store, "both")  # other users unaffected


def test_trust_accepts_changed_key_only_when_confirmed(w, tmp_path, user_keys):
    store = ClientStore(tmp_path / "s")
    keys.sync(store, api(w, "sender"), include_moderators=False)
    old_pin = store.load_pins()["recipient"]
    swap_key_in_db(w, "recipient", user_keys[5])
    keys.sync(store, api(w, "sender"), include_moderators=False)

    # A confirm function that records what it was shown, then says no.
    shown = []

    def record_and_decline(old, new):
        shown.append({"old": old, "new": new})
        return False

    assert keys.trust(store, "recipient", record_and_decline) is False
    assert store.load_pins()["recipient"] == old_pin   # declined: pin unchanged
    assert shown[0]["old"] == old_pin                  # both fingerprints were shown
    assert shown[0]["new"] != old_pin

    assert keys.trust(store, "recipient", always_no) is False
    assert keys.trust(store, "recipient", always_yes) is True
    keys.trusted_key(store, "recipient")               # now allowed


def test_server_cannot_substitute_own_key(w, tmp_path, user_keys):
    """A recipient syncing sees their own key; a swapped one is flagged and cannot be trusted."""
    store = ClientStore(tmp_path / "r")
    response = w["client"].get("/directory", headers=auth_header(w["tokens"]["recipient"]))
    own = None
    for entry in response.json()["recipients"]:
        if entry["username"] == "recipient":
            own = entry
    store.save_identity({"username": "recipient", "key_id": own["key_id"], "fingerprint": own["fingerprint"]})

    swap_key_in_db(w, "recipient", user_keys[5])
    results = keys.sync(store, api(w, "recipient"), include_moderators=False)
    assert status_by_username(results)["recipient"] == keys.STATUS_CHANGED
    with pytest.raises(ClientError, match="own key"):
        keys.trust(store, "recipient", always_yes)


def test_inconsistent_entry_is_not_cached(w, tmp_path):
    conn = db.connect(w["paths"].db)
    conn.execute("UPDATE public_keys SET fingerprint = ? WHERE key_id = ?", ("0" * 64, w["ids"]["both_key"]))
    conn.close()
    store = ClientStore(tmp_path / "s")
    results = keys.sync(store, api(w, "sender"), include_moderators=False)
    assert status_by_username(results)["both"] == keys.STATUS_INVALID
    assert "both" not in store.load_directory_cache()["recipients"]
    assert "both" not in store.load_pins()


def test_revoked_user_dropped_from_cache_but_pin_kept(w, tmp_path):
    store = ClientStore(tmp_path / "s")
    keys.sync(store, api(w, "sender"), include_moderators=False)
    url = f"/admin/keys/{w['ids']['recipient_key']}/revoke"
    w["client"].post(url, headers=auth_header(w["tokens"]["admin"]))
    keys.sync(store, api(w, "sender"), include_moderators=False)
    assert "recipient" not in store.load_directory_cache()["recipients"]
    assert "recipient" in store.load_pins()
    with pytest.raises(ClientError, match="not in the local directory"):
        keys.trusted_key(store, "recipient")


def test_fingerprint_info_and_format(w, tmp_path):
    store = ClientStore(tmp_path / "s")
    keys.sync(store, api(w, "sender"), include_moderators=False)
    info = keys.fingerprint_info(store, "recipient")
    assert info["pinned"] == info["fingerprint"]
    groups = format_fingerprint(info["fingerprint"]).split(" ")
    assert len(groups) == 8
    for group in groups:
        assert len(group) == 8
    with pytest.raises(ClientError):
        keys.fingerprint_info(store, "nobody")
