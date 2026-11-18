"""Stage 7: envelopes, anonymous send, inbox."""

import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import PASSPHRASE, Setup, auth_header, build_world, count_action, make_client_factory
from whisperchain.client.api import ApiClient
from whisperchain.client.commands import keys, messages
from whisperchain.client.commands import tokens as token_cmd
from whisperchain.client.errors import ApiError, ClientError, NetworkError
from whisperchain.client.store import ClientStore
from whisperchain.common import constants as C
from whisperchain.common.encoding import b64_to_int, b64d, b64e, int_to_b64
from whisperchain.common.envelope import (
    DECRYPT_FAILED, EnvelopeError, build_envelope, decrypt_envelope, pad, parse_header, unpad)

KEY_ID = "0b7b6f3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b"            # a valid uuid4 for unit tests


def without_last_byte(data: bytes) -> bytes:
    return data[0:len(data) - 1]


# ---------------------------------------------------------------------------
# Envelope unit tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def recipient_key(user_keys):
    return user_keys[0]


def test_envelope_round_trip_and_size(recipient_key):
    for text in ["hi", "", "unicode ✓ ünïcødé", "x" * C.MAX_MESSAGE_BYTES]:
        envelope = build_envelope(text, recipient_key.public_key(), KEY_ID, 3)
        assert len(envelope) == C.ENVELOPE_BYTES
        assert len(envelope) == 1453
        message, content_key = decrypt_envelope(envelope, recipient_key, 3)
        assert message == text
        assert len(content_key) == 32


def test_message_too_long_rejected(recipient_key):
    with pytest.raises(EnvelopeError):
        build_envelope("x" * (C.MAX_MESSAGE_BYTES + 1), recipient_key.public_key(), KEY_ID, 1)
    with pytest.raises(EnvelopeError):  # 334 three-byte characters = 1002 bytes
        pad("✓" * 334)


def test_padding_round_trip_and_checks():
    block = pad("abc")
    assert len(block) == 1024
    assert unpad(block) == "abc"
    with pytest.raises(EnvelopeError):
        unpad(without_last_byte(block) + b"\x01")   # non-zero padding


def test_any_single_flipped_bit_fails(recipient_key):
    """Flip one random bit in every byte of the envelope: every copy must fail."""
    envelope = build_envelope("tamper test", recipient_key.public_key(), KEY_ID, 1)
    for position in range(len(envelope)):
        tampered = bytearray(envelope)          # a changeable copy of the bytes
        bit = 2 ** secrets.randbelow(8)         # one of 1, 2, 4, ... 128
        # ^ is XOR: it flips exactly the chosen bit and leaves the others alone.
        tampered[position] = tampered[position] ^ bit
        with pytest.raises(EnvelopeError) as exc:
            decrypt_envelope(bytes(tampered), recipient_key, 1)
        assert str(exc.value) == DECRYPT_FAILED   # uniform error, no detail leaked


def test_wrong_key_fails(user_keys):
    envelope = build_envelope("secret", user_keys[0].public_key(), KEY_ID, 1)
    with pytest.raises(EnvelopeError, match=DECRYPT_FAILED):
        decrypt_envelope(envelope, user_keys[1], 1)


def test_wrong_round_fails(recipient_key):
    """The round is in the AAD: a message cannot be replayed into another round."""
    envelope = build_envelope("secret", recipient_key.public_key(), KEY_ID, 1)
    with pytest.raises(EnvelopeError):
        decrypt_envelope(envelope, recipient_key, 2)


def test_parse_header_rejects_malformed(recipient_key):
    envelope = build_envelope("x", recipient_key.public_key(), KEY_ID, 1)
    assert parse_header(envelope)["key_id"] == KEY_ID
    for bad in [without_last_byte(envelope), envelope + b"\x00", b""]:
        with pytest.raises(EnvelopeError, match="length"):
            parse_header(bad)
    with pytest.raises(EnvelopeError, match="version"):
        parse_header(b"\x02" + envelope[1:])                       # version 2 instead of 1
    with pytest.raises(EnvelopeError, match="key id"):
        parse_header(envelope[0:1] + b"\x00" * 16 + envelope[17:])  # all-zero key id: not a uuid4


# ---------------------------------------------------------------------------
# A world where "sender" holds a token and has synced the directory
# ---------------------------------------------------------------------------

@pytest.fixture
def s(fresh_world, tmp_path, user_keys):
    return Setup(fresh_world, tmp_path, user_keys)


def last_item(items):
    return items[len(items) - 1]


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------

def test_send_and_read(s):
    assert s.send(text="meet at noon")["status"] == "sent"
    assert s.sender.load_token(1) is None
    assert s.sender.load_outbox() is None

    inbox = messages.list_inbox(s.api("recipient"))
    assert len(inbox) == 1
    assert inbox[0]["round"] == 1
    result = messages.read_message(s.recipient, s.api("recipient"), inbox[0]["id"], PASSPHRASE)
    assert result["text"] == "meet at noon"


def test_send_response_is_bare(s):
    response = s.post(s.raw_body())
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}   # never the message id


def test_audit_entries_for_send_and_inbox(s):
    s.send()
    messages.list_inbox(s.api("recipient"))
    log = s.audit()
    assert ("MESSAGE_SENT", "Sender", "round: 1") in log
    assert last_item(log) == ("INBOX_FETCHED", "Recipient", "")


def test_no_authorization_header_on_send(tmp_path, user_keys):
    seen = []  # headers of every request to /messages

    def record_headers(app):
        # Middleware runs for every request before the route does. FastAPI
        # requires middleware to be written as an `async` function; `await`
        # waits for the real route to produce its response.
        @app.middleware("http")
        async def spy(request, call_next):
            if request.url.path == "/messages":
                header_names = []
                for name in request.headers.keys():
                    header_names.append(name.lower())
                seen.append(header_names)
            return await call_next(request)

    world = build_world(tmp_path / "server_data", user_keys, app_hook=record_headers)
    setup = Setup(world, tmp_path, user_keys)
    # The client is given a logged-in ApiClient, and still must not use it for sending.
    setup.send(api=setup.api("sender"))
    assert len(seen) == 1
    assert "authorization" not in seen[0]
    assert "cookie" not in seen[0]


def test_send_never_reads_session(s, monkeypatch):
    def forbidden_load_session(self):
        raise AssertionError("send path read session.json")

    # monkeypatch swaps ClientStore.load_session for our function, only for
    # the duration of this test.
    monkeypatch.setattr(ClientStore, "load_session", forbidden_load_session)
    assert s.send()["status"] == "sent"


# ---------------------------------------------------------------------------
# Server validation
# ---------------------------------------------------------------------------

def test_wrong_length_envelope_rejected(s):
    body = s.raw_body()
    body["envelope"] = b64e(without_last_byte(b64d(body["envelope"])))
    assert s.post(body).status_code == 400


@pytest.mark.parametrize("problem", ["unknown_user", "not_a_recipient", "wrong_key", "revoked_key", "inactive"])
def test_bad_recipient_does_not_burn_token(s, problem):
    body = s.raw_body()
    admin = auth_header(s.w["tokens"]["admin"])
    if problem == "unknown_user":
        body["recipient"] = "nobody"
    elif problem == "not_a_recipient":
        body["recipient"] = "sender"
    elif problem == "wrong_key":
        body = s.raw_body(to="recipient", key_owner="both")   # encrypted to someone else's key
    elif problem == "revoked_key":
        s.w["client"].post(f"/admin/keys/{s.w['ids']['recipient_key']}/revoke", headers=admin)
    elif problem == "inactive":
        s.w["client"].post(f"/admin/users/{s.w['ids']['recipient']}/deactivate", headers=admin)

    response = s.post(body)
    assert response.status_code == 409
    assert response.json()["detail"]["reason"] == "bad_recipient"
    assert s.message_count() == 0
    # The same token still works for a valid recipient.
    assert s.post(s.raw_body(to="both")).status_code == 200


def test_idempotent_resend_vs_replay(s):
    body = s.raw_body(text="first")
    assert s.post(body).status_code == 200
    assert s.post(body).status_code == 200       # identical retry: accepted, nothing new
    assert s.message_count() == 1
    assert count_action(s.audit(), "MESSAGE_SENT") == 1

    replay = s.raw_body(text="different envelope, same token")
    response = s.post(replay)
    assert response.status_code == 409
    assert response.json()["detail"]["reason"] == "replay"
    assert s.message_count() == 1


def test_bad_signature_rejected(s):
    body = s.raw_body()
    body["s"] = int_to_b64(b64_to_int(body["s"]) + 1)
    response = s.post(body)
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "bad_signature"


def test_closed_round_token_rejected(s):
    body = s.raw_body()
    s.w["client"].post("/admin/rounds/start", headers=auth_header(s.w["tokens"]["admin"]))
    response = s.post(body)
    assert response.status_code == 409
    assert response.json()["detail"]["reason"] == "closed_round"


def test_token_from_one_round_cannot_claim_another(s):
    """Re-labelling a round-1 token as round 2 fails: round 2 has a different key."""
    s.w["client"].post("/admin/rounds/start", headers=auth_header(s.w["tokens"]["admin"]))
    keys.sync(s.sender, s.api("sender"), include_moderators=False)
    body = s.raw_body()
    entry, public_key = keys.trusted_key(s.sender, "recipient")
    body["round"] = 2
    body["envelope"] = b64e(build_envelope("x", public_key, entry["key_id"], 2))
    assert s.post(body).json()["detail"]["reason"] == "bad_signature"


def test_rollback_leaves_token_unspent(s, monkeypatch):
    audit = s.app.state.audit
    original_append = audit.append_audit

    # A replacement that fails exactly when the message would be recorded.
    def failing_append(conn, action, role, detail=""):
        if action == "MESSAGE_SENT":
            raise RuntimeError("disk full")
        return original_append(conn, action, role, detail)

    monkeypatch.setattr(audit, "append_audit", failing_append)
    body = s.raw_body()
    with pytest.raises(RuntimeError):
        s.post(body)
    assert s.message_count() == 0   # message insert rolled back with the audit

    monkeypatch.setattr(audit, "append_audit", original_append)
    assert s.post(body).status_code == 200   # token was never consumed


def test_spend_rejected_audited_once_per_reason(s):
    body = s.raw_body()
    body["s"] = int_to_b64(b64_to_int(body["s"]) + 1)
    for _ in range(5):
        s.post(body)
    rejected = []
    for row in s.audit():
        if row[0] == "SPEND_REJECTED":
            rejected.append(row)
    assert rejected == [("SPEND_REJECTED", "Sender", "reason: bad_signature")]
    assert s.app.state.rejections.recent_count() == 5   # all still counted in memory


# ---------------------------------------------------------------------------
# Client send behaviour
# ---------------------------------------------------------------------------

class LostResponseApi(ApiClient):
    """An ApiClient whose send reaches the server, but whose answer is lost."""

    def send_message(self, body):
        ApiClient.send_message(self, body)   # the real send
        raise NetworkError("connection dropped")


def test_lost_response_resubmits_same_envelope(s):
    lossy = LostResponseApi(make_client_factory(s.app))
    with pytest.raises(ClientError, match="resubmit"):
        s.send(text="important", api=lossy)
    assert s.sender.load_token(1) is not None
    assert s.sender.load_outbox() is not None

    # Next run resubmits the SAME envelope: accepted as a retry, not a replay.
    assert s.send(text="ignored")["status"] == "resubmitted"
    assert s.message_count() == 1
    assert s.sender.load_token(1) is None
    assert s.sender.load_outbox() is None


def test_client_bad_recipient_keeps_token(s):
    url = f"/admin/keys/{s.w['ids']['recipient_key']}/revoke"
    s.w["client"].post(url, headers=auth_header(s.w["tokens"]["admin"]))
    with pytest.raises(ClientError, match="NOT used"):
        s.send()   # the local cache still has the revoked key
    assert s.sender.load_token(1) is not None
    assert s.sender.load_outbox() is None
    assert s.send(to="both")["status"] == "sent"


def test_client_replay_deletes_dead_token(s):
    assert s.post(s.raw_body()).status_code == 200   # token spent behind the client's back
    with pytest.raises(ApiError) as exc:
        s.send()
    assert exc.value.reason == "replay"
    assert s.sender.load_token(1) is None


class NoNetworkApi(ApiClient):
    """Fails the test if the code under test tries to use the network."""

    def current_round(self):
        raise AssertionError("network used")


def unused_factory():
    raise AssertionError("network used")


def test_client_rejects_long_message_before_network(s):
    with pytest.raises(ClientError, match="maximum"):
        messages.send(s.sender, NoNetworkApi(unused_factory), "recipient", "x" * 1001, now=True)


def test_client_refuses_on_pin_mismatch(s):
    pins = s.sender.load_pins()
    pins["recipient"] = "0" * 64
    s.sender.save_pins(pins)
    with pytest.raises(ClientError, match="does NOT match"):
        s.send()
    assert s.sender.load_token(1) is not None


def test_random_delay_used_unless_now(s):
    s.sender.save_config({"send_delay_min": 5, "send_delay_max": 60})
    # Instead of really sleeping, record how long send() asked to sleep.
    requested_sleeps = []

    def fake_sleep(seconds):
        requested_sleeps.append(seconds)

    messages.send(s.sender, s.api(), "recipient", "hi", now=False, sleep=fake_sleep)
    assert len(requested_sleeps) == 1
    assert requested_sleeps[0] >= 5
    assert requested_sleeps[0] <= 60


def test_no_token_means_no_send(s):
    s.send()
    with pytest.raises(ClientError, match="token request"):
        s.send()


# ---------------------------------------------------------------------------
# Inbox
# ---------------------------------------------------------------------------

def test_inbox_only_own_messages(s):
    s.send()
    own = messages.list_inbox(s.api("recipient"))
    assert len(own) == 1
    assert messages.list_inbox(s.api("both")) == []
    # Someone else's message id is simply "not in your inbox".
    other = ClientStore(s.recipient.dir.parent / "both")
    with pytest.raises(ClientError, match="no such message"):
        messages.read_message(other, s.api("both"), own[0]["id"], PASSPHRASE)


def test_inbox_sanitizes_control_characters(s):
    s.send(text="hi\x1b[2J\x07 there\x9b")
    entry = messages.list_inbox(s.api("recipient"))[0]
    result = messages.read_message(s.recipient, s.api("recipient"), entry["id"], PASSPHRASE)
    assert result["text"] == "hi[2J there"


def test_inbox_undecryptable_message_reported_uniformly(s):
    s.send()
    entry = messages.list_inbox(s.api("recipient"))[0]
    wrong = ClientStore(s.recipient.dir.parent / "wrongkey")
    wrong.save_private_key(rsa.generate_private_key(public_exponent=65537, key_size=3072), PASSPHRASE)
    result = messages.read_message(wrong, s.api("recipient"), entry["id"], PASSPHRASE)
    assert result["text"] is None
    assert result["error"] == DECRYPT_FAILED


def test_inbox_ordered_by_round(s):
    s.send(text="round one")
    s.w["client"].post("/admin/rounds/start", headers=auth_header(s.w["tokens"]["admin"]))
    token_cmd.request_token(s.sender, s.api("sender"))
    s.send(text="round two")
    rounds = []
    for message in messages.list_inbox(s.api("recipient")):
        rounds.append(message["round"])
    assert rounds == [1, 2]
