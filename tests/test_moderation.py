"""Stage 8: flagging, moderator review, freeze/dismiss, alert rules."""

import pytest

from conftest import (PASSPHRASE, PASSWORD, Setup, always_no, always_yes, auth_header, build_world,
                      count_action, invite_directly, register_raw)
from whisperchain.client.commands import messages, moderation
from whisperchain.client.commands import tokens as token_cmd
from whisperchain.client.errors import ApiError, ClientError
from whisperchain.common import blind
from whisperchain.common import constants as C
from whisperchain.common.encoding import b64_to_int, b64d, b64e, int_to_b64
from whisperchain.server import db


@pytest.fixture
def s(fresh_world, tmp_path, user_keys):
    return Setup(fresh_world, tmp_path, user_keys)


def setup_with_config(tmp_path, user_keys, config: dict):
    """Like the `s` fixture, but with some server settings changed."""
    world = build_world(tmp_path / "server_data", user_keys, config=config)
    return Setup(world, tmp_path, user_keys)


def inbox_ids(s, who="recipient") -> list[str]:
    ids = []
    for message in messages.list_inbox(s.api(who)):
        ids.append(message["id"])
    return ids


def only_message_id(s) -> str:
    """The id of the single message in the recipient's inbox."""
    ids = inbox_ids(s)
    assert len(ids) == 1
    return ids[0]


def flag(s, message_id, reason="spam", confirm=always_yes):
    """Flag a message as the recipient, through the real client code."""
    return moderation.flag(s.recipient, s.api("recipient"), message_id, PASSPHRASE, reason, confirm)


def alerts(s) -> list[str]:
    """The detail of every ALERT entry, e.g. ["rule: MODERATOR_GRANTED", ...]."""
    details = []
    for row in s.audit():
        if row[0] == "ALERT":
            details.append(row[2])
    return details


# ---------------------------------------------------------------------------
# Full end-to-end: issue, send, receive, flag, review, freeze
# ---------------------------------------------------------------------------

def test_full_moderation_flow(s):
    body = s.raw_body(text="this is abusive")
    assert s.post(body).status_code == 200                       # issue + send (token from Setup)
    message_id = only_message_id(s)                               # receive

    result = flag(s, message_id, reason="harassment")             # flag
    assert result["moderator_copies"] == 1
    assert result["decryptable"] is True

    queue = moderation.queue(s.api("moderator"))
    assert len(queue) == 1
    assert queue[0]["id"] == result["flag_id"]
    assert queue[0]["status"] == "open"
    assert queue[0]["reason"] == "harassment"

    review = moderation.review(s.moderator, s.api("moderator"), result["flag_id"], PASSPHRASE)
    assert review["text"] == "this is abusive"                   # moderator can read it

    moderation.freeze(s.api("moderator"), result["flag_id"])      # freeze
    assert moderation.queue(s.api("moderator"))[0]["status"] == "actioned"

    # The frozen token is refused, even as an identical "retry".
    response = s.post(body)
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "frozen"

    # The audit log recorded each step, by role and flag id only.
    flag_detail = "flag: " + result["flag_id"]
    log = s.audit()
    assert ("MESSAGE_FLAGGED", "Recipient", flag_detail) in log
    assert ("FLAG_REVIEWED", "Moderator", flag_detail) in log
    assert ("TOKEN_FROZEN", "Moderator", flag_detail) in log
    assert ("SPEND_REJECTED", "Sender", "reason: frozen") in log


def test_moderator_sees_no_recipient_or_token_data(s):
    body = s.raw_body(text="x")
    s.post(body)
    message_id = only_message_id(s)
    flag_id = flag(s, message_id)["flag_id"]

    queue = moderation.queue(s.api("moderator"))
    assert sorted(queue[0]) == ["created_at", "id", "reason", "round", "status"]
    response = s.w["client"].get(f"/mod/flags/{flag_id}", headers=auth_header(s.w["tokens"]["moderator"]))
    review = response.json()
    assert sorted(review) == ["ciphertext", "created_at", "id", "key_id", "nonce", "reason",
                              "round", "status", "version", "wrapped_key"]

    # (The field names above already show no user id is present; a small
    # numeric id could appear by chance inside base64, so it is not searched.)
    token_hash = blind.token_hash(b64d(body["t"]))
    everything_shown = str(queue) + str(review)
    for value in ["recipient", message_id, token_hash, body["t"]]:
        assert value not in everything_shown, value


def test_flag_only_own_messages(s):
    s.post(s.raw_body())
    message_id = only_message_id(s)
    response = s.w["client"].post(f"/messages/{message_id}/flag", json={"reason": "x"},
                                  headers=auth_header(s.w["tokens"]["both"]))
    assert response.status_code == 404                           # not 403: existence not revealed
    flag(s, message_id)
    with pytest.raises(ApiError) as exc:
        flag(s, message_id)
    assert exc.value.status == 409                               # already flagged


def test_flag_rejects_bad_wrapped_keys(s):
    s.post(s.raw_body())
    message_id = only_message_id(s)
    url = f"/messages/{message_id}/flag"
    headers = auth_header(s.w["tokens"]["recipient"])
    right_length = b64e(b"\x00" * C.WRAPPED_KEY_BYTES)

    # A key copy for someone who is not a moderator.
    not_a_moderator = {s.w["ids"]["both_key"]: right_length}
    response = s.w["client"].post(url, json={"reason": "", "wrapped_keys": not_a_moderator}, headers=headers)
    assert response.status_code == 400

    # A key copy with the wrong length.
    too_short = {s.w["ids"]["moderator_key"]: b64e(b"short")}
    response = s.w["client"].post(url, json={"reason": "", "wrapped_keys": too_short}, headers=headers)
    assert response.status_code == 400

    # A reason longer than 200 characters.
    response = s.w["client"].post(url, json={"reason": "x" * 201}, headers=headers)
    assert response.status_code == 422


def test_undecryptable_flag(s):
    """A sender can submit garbage with a valid header; the recipient can still flag it."""
    body = s.raw_body()
    envelope = bytearray(b64d(body["envelope"]))
    # Keep the version byte and the 16-byte key id; set everything after to zero.
    for position in range(17, len(envelope)):
        envelope[position] = 0
    body["envelope"] = b64e(bytes(envelope))
    assert s.post(body).status_code == 200
    message_id = only_message_id(s)

    result = flag(s, message_id)
    assert result["moderator_copies"] == 0
    assert result["decryptable"] is False
    review = moderation.review(s.moderator, s.api("moderator"), result["flag_id"], PASSPHRASE)
    assert review["text"] is None
    assert "no content available" in review["note"]


def test_moderator_with_changed_key_gets_no_copy(s):
    s.post(s.raw_body())
    message_id = only_message_id(s)
    s.recipient.save_pins({"moderator": "0" * 64})              # our pin disagrees with the server
    seen = {}

    def record_and_agree(names, skipped):
        seen["names"] = names
        seen["skipped"] = skipped
        return True

    assert flag(s, message_id, confirm=record_and_agree)["moderator_copies"] == 0
    assert seen["names"] == []
    assert seen["skipped"] == ["moderator"]


def test_flag_cancelled_sends_nothing(s):
    s.post(s.raw_body())
    message_id = only_message_id(s)
    with pytest.raises(ClientError, match="cancelled"):
        flag(s, message_id, confirm=always_no)
    assert moderation.queue(s.api("moderator")) == []


def test_dismiss_and_resolution_rules(s):
    s.post(s.raw_body())
    message_id = only_message_id(s)
    flag_id = flag(s, message_id)["flag_id"]
    moderation.dismiss(s.api("moderator"), flag_id)
    assert moderation.queue(s.api("moderator"))[0]["status"] == "dismissed"
    with pytest.raises(ApiError) as exc:
        moderation.freeze(s.api("moderator"), flag_id)           # already resolved
    assert exc.value.status == 409
    assert ("FLAG_DISMISSED", "Moderator", "flag: " + flag_id) in s.audit()


def test_flag_reason_sanitized_on_display(s):
    s.post(s.raw_body())
    message_id = only_message_id(s)
    flag_id = flag(s, message_id, reason="bad\x1b[2J stuff")["flag_id"]
    review = moderation.review(s.moderator, s.api("moderator"), flag_id, PASSPHRASE)
    assert review["reason"] == "bad[2J stuff"


def test_freeze_does_not_affect_future_rounds(s):
    """TA clarification: freezing cannot block the sender's next, unlinkable token."""
    s.post(s.raw_body())
    message_id = only_message_id(s)
    flag_id = flag(s, message_id)["flag_id"]
    moderation.freeze(s.api("moderator"), flag_id)
    s.w["client"].post("/admin/rounds/start", headers=auth_header(s.w["tokens"]["admin"]))
    token_cmd.request_token(s.sender, s.api("sender"))
    assert s.send()["status"] == "sent"


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def flag_messages_in_round(s, count_flagged):
    """sender, both and victim (the three Sender accounts) each send one message
    to recipient in round 1; the recipient then flags `count_flagged` of them."""
    senders = [s.sender, s.make_sender("both"), s.make_sender("victim")]
    number = 0
    for sender in senders:
        s.send(text=f"msg {number}", sender=sender)
        number = number + 1
    ids = inbox_ids(s)
    for position in range(count_flagged):
        flag(s, ids[position])


def test_flag_rate_alert_fires_once(tmp_path, user_keys):
    s = setup_with_config(tmp_path, user_keys, {"alert_recipient_share_min_flags": 99})
    flag_messages_in_round(s, 3)                                 # 3 flags, 100% of the round
    assert alerts(s).count("rule: FLAG_RATE") == 1
    assert "rule: RECIPIENT_FLAG_SHARE" not in alerts(s)


def test_flag_rate_needs_enough_flags(tmp_path, user_keys):
    s = setup_with_config(tmp_path, user_keys, {"alert_recipient_share_min_flags": 99})
    flag_messages_in_round(s, 2)                                 # 2 < 3 flags
    assert "rule: FLAG_RATE" not in alerts(s)


def test_flag_rate_needs_the_fraction(tmp_path, user_keys):
    config = {
        "alert_recipient_share_min_flags": 99,
        "alert_flag_rate_min_flags": 1,
        "alert_flag_rate_min_fraction": 0.5,
    }
    s = setup_with_config(tmp_path, user_keys, config)
    flag_messages_in_round(s, 1)                                 # 1/3 = 33% < 50%
    assert "rule: FLAG_RATE" not in alerts(s)


def test_recipient_flag_share_alert(tmp_path, user_keys):
    s = setup_with_config(tmp_path, user_keys, {"alert_flag_rate_min_flags": 99})
    flag_messages_in_round(s, 3)
    assert alerts(s).count("rule: RECIPIENT_FLAG_SHARE") == 1

    conn = db.connect(s.w["paths"].db)
    scopes = []
    for row in conn.execute("SELECT scope FROM alert_state WHERE rule = 'RECIPIENT_FLAG_SHARE'"):
        scopes.append(row["scope"])
    conn.close()
    # The recipient id is only in alert_state, never in the audit log.
    assert scopes == [f"recipient:{s.w['ids']['recipient']}:round:1"]


def test_rejection_burst_alert(s):
    body = s.raw_body()
    body["s"] = int_to_b64(b64_to_int(body["s"]) + 1)            # bad signature
    for _ in range(15):
        s.post(body)
    assert alerts(s).count("rule: REJECTION_BURST") == 1
    # The rejections themselves were still only audited once.
    assert count_action(s.audit(), "SPEND_REJECTED") == 1


def test_moderator_granted_alert(s, user_keys):
    before = alerts(s).count("rule: MODERATOR_GRANTED")
    admin = auth_header(s.w["tokens"]["admin"])
    url = f"/admin/users/{s.w['ids']['victim']}/roles"
    s.w["client"].post(url, json={"roles": ["Sender", "Moderator"]}, headers=admin)
    assert alerts(s).count("rule: MODERATOR_GRANTED") == before + 1
    s.w["client"].post(url, json={"roles": ["Moderator"]}, headers=admin)   # already a Moderator: no new grant
    assert alerts(s).count("rule: MODERATOR_GRANTED") == before + 1

    # Registering with a Moderator invite is also a grant.
    invite = invite_directly(s.w["paths"], ["Moderator"])
    response = register_raw(s.w["client"], user_keys[5], invite, "newmod", PASSWORD)
    assert response.status_code == 200
    assert alerts(s).count("rule: MODERATOR_GRANTED") == before + 2


def test_alert_entries_do_not_retrigger_alerts(s):
    calls = []
    original_hook = s.app.state.alerts.after_append

    # Wrap the alert hook so we can see which actions it is called for.
    def spy(audit, conn, action, detail):
        calls.append(action)
        return original_hook(audit, conn, action, detail)

    s.app.state.audit.on_append = spy
    admin = auth_header(s.w["tokens"]["admin"])
    url = f"/admin/users/{s.w['ids']['victim']}/roles"
    s.w["client"].post(url, json={"roles": ["Moderator"]}, headers=admin)
    # The ALERT append reached the hook, and the hook did nothing with it.
    assert calls == ["ROLES_CHANGED", "ALERT"]
    assert alerts(s).count("rule: MODERATOR_GRANTED") == 2       # world's moderator + this grant, no more
