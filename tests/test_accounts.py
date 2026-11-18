"""Stage 2: invites, key validation, proof of possession, register, login, JWT."""

import os
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi.testclient import TestClient

from conftest import PASSPHRASE, PASSWORD, api_client, invite_directly, register_raw
from whisperchain.client.api import ApiClient, build_client_factory
from whisperchain.client.commands import account
from whisperchain.client.errors import ApiError, ClientError, NetworkError
from whisperchain.client.store import ClientStore
from whisperchain.common.encoding import b64e
from whisperchain.common.fingerprint import fingerprint, public_key_der
from whisperchain.server import auth, db
from whisperchain.server.app import create_app
from whisperchain.server.ratelimit import SlidingWindowLimiter
from whisperchain.server.routes.accounts import RegisterRequest


def count_users(server_paths) -> int:
    conn = db.connect(server_paths.db)
    try:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# End-to-end through the client commands
# ---------------------------------------------------------------------------

def test_client_register_and_login_end_to_end(tmp_path, app, server_paths, user_keys):
    store = ClientStore(tmp_path / "alice")
    invite = invite_directly(server_paths, ["Sender", "Recipient"])
    key = user_keys[0]

    result = account.register(store, api_client(app), invite, "alice", PASSWORD, PASSPHRASE, private_key=key)
    assert sorted(result["roles"]) == ["Recipient", "Sender"]

    # Identity saved, fingerprint matches the key we generated.
    identity = store.load_identity()
    assert identity["username"] == "alice"
    assert identity["fingerprint"] == fingerprint(public_key_der(key.public_key()))

    # Private key is stored encrypted: right passphrase opens it, wrong does not.
    assert b"ENCRYPTED" in store.private_key_path.read_bytes()
    assert store.load_private_key(PASSPHRASE).private_numbers() == key.private_numbers()
    with pytest.raises(ClientError):
        store.load_private_key("wrong-passphrase-123")

    login = account.login(store, api_client(app), "alice", PASSWORD)
    assert sorted(login["roles"]) == ["Recipient", "Sender"]
    assert store.load_session()["token"] == login["token"]


def test_client_files_are_private(tmp_path, app, server_paths, user_keys):
    store = ClientStore(tmp_path / "bob")
    invite = invite_directly(server_paths, ["Sender"])
    account.register(store, api_client(app), invite, "bob", PASSWORD, PASSPHRASE, private_key=user_keys[1])
    if os.name != "nt":
        # st_mode & 0o777 keeps just the permission bits of the file mode.
        assert store.private_key_path.stat().st_mode & 0o777 == 0o600
        assert store.identity_path.stat().st_mode & 0o777 == 0o600
        assert store.dir.stat().st_mode & 0o777 == 0o700


def test_client_refuses_same_password_and_passphrase(tmp_path, app, server_paths):
    store = ClientStore(tmp_path / "c")
    invite = invite_directly(server_paths, ["Sender"])
    with pytest.raises(ClientError, match="different"):
        account.register(store, api_client(app), invite, "carol", PASSWORD, PASSWORD)
    assert not store.has_private_key()


def test_client_deletes_key_on_definitive_failure(tmp_path, app, user_keys):
    store = ClientStore(tmp_path / "d")
    with pytest.raises(ApiError):
        account.register(store, api_client(app), "no-such-invite", "dave", PASSWORD, PASSPHRASE,
                         private_key=user_keys[2])
    assert not store.has_private_key()


def test_client_keeps_key_on_network_failure(tmp_path, user_keys):
    # A fake network where every request fails to connect.
    def broken_network(request):
        raise httpx.ConnectError("down")

    def broken_client_factory():
        return httpx.Client(base_url="http://x", transport=httpx.MockTransport(broken_network))

    api = ApiClient(broken_client_factory)
    store = ClientStore(tmp_path / "e")
    with pytest.raises(NetworkError):
        account.register(store, api, "code", "erin", PASSWORD, PASSPHRASE, private_key=user_keys[2])
    # Outcome unknown, so the key must survive.
    assert store.has_private_key()


def test_client_refuses_plain_http_without_flag(tmp_path):
    with pytest.raises(ClientError, match="http"):
        build_client_factory("http://localhost:8443", None, insecure_dev=False)
    build_client_factory("http://localhost:8443", None, insecure_dev=True)  # allowed
    with pytest.raises(ClientError, match="CA certificate"):
        build_client_factory("https://localhost:8443", None)


# ---------------------------------------------------------------------------
# Invites
# ---------------------------------------------------------------------------

def test_used_invite_rejected(client, server_paths, user_keys):
    invite = invite_directly(server_paths, ["Sender"])
    assert register_raw(client, user_keys[0], invite, "user1").status_code == 200
    response = register_raw(client, user_keys[1], invite, "user2")
    assert response.status_code == 400
    assert "invite" in response.json()["detail"]


def test_expired_invite_rejected(client, server_paths, user_keys):
    invite = invite_directly(server_paths, ["Sender"])
    conn = db.connect(server_paths.db)
    one_second_ago = datetime.now(timezone.utc) - timedelta(seconds=1)
    conn.execute("UPDATE invites SET expires_at = ?", (one_second_ago.isoformat(),))
    conn.close()
    assert register_raw(client, user_keys[0], invite, "user1").status_code == 400


def test_invite_cannot_grant_admin(server_paths):
    with pytest.raises(ValueError):
        invite_directly(server_paths, ["Admin"])


def test_invite_stored_only_as_hash(server_paths):
    invite = invite_directly(server_paths, ["Sender"])
    conn = db.connect(server_paths.db)
    stored = conn.execute("SELECT code_hash FROM invites").fetchone()[0]
    conn.close()
    assert invite not in stored
    assert len(stored) == 64  # a SHA-256 hash in hex


def test_bad_key_does_not_burn_invite(client, server_paths, user_keys):
    invite = invite_directly(server_paths, ["Sender"])
    small_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    body = {
        "invite_code": invite,
        "username": "user1",
        "password": PASSWORD,
        "public_key": b64e(public_key_der(small_key.public_key())),
        "challenge_id": "x",
        "challenge_response": b64e(b"x"),
    }
    assert client.post("/register", json=body).status_code == 400
    # Bad password with a good key also must not burn it.
    assert register_raw(client, user_keys[0], invite, "user1", password="short").status_code == 400
    # The invite still works.
    assert register_raw(client, user_keys[0], invite, "user1").status_code == 200


def test_taken_username_does_not_burn_invite(client, server_paths, user_keys):
    first_invite = invite_directly(server_paths, ["Sender"])
    assert register_raw(client, user_keys[0], first_invite, "same").status_code == 200
    invite = invite_directly(server_paths, ["Sender"])
    assert register_raw(client, user_keys[1], invite, "same").status_code == 409
    assert register_raw(client, user_keys[1], invite, "other").status_code == 200


# ---------------------------------------------------------------------------
# No role on registration
# ---------------------------------------------------------------------------

def test_register_model_has_no_role_field():
    for field_name in RegisterRequest.model_fields:
        assert "role" not in field_name


def test_role_field_in_request_is_rejected(client, server_paths, user_keys):
    invite = invite_directly(server_paths, ["Sender"])
    response = register_raw(client, user_keys[0], invite, "sneaky", extra_fields={"roles": ["Admin"]})
    assert response.status_code == 422
    assert count_users(server_paths) == 0
    # Roles really do come from the invite.
    ok = register_raw(client, user_keys[0], invite, "sneaky")
    assert ok.json()["roles"] == ["Sender"]


# ---------------------------------------------------------------------------
# Key validation and proof of possession
# ---------------------------------------------------------------------------

def make_rsa_2048_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_rsa_exponent_3_key():
    return rsa.generate_private_key(public_exponent=3, key_size=3072)


def make_ed25519_key():
    return ed25519.Ed25519PrivateKey.generate()


# parametrize: pytest runs the test once for each function in the list.
@pytest.mark.parametrize("make_key", [make_rsa_2048_key, make_rsa_exponent_3_key, make_ed25519_key])
def test_challenge_rejects_bad_keys(client, make_key):
    der = public_key_der(make_key().public_key())
    assert client.post("/register/challenge", json={"public_key": b64e(der)}).status_code == 400


def test_challenge_rejects_noncanonical_and_garbage(client, user_keys):
    der = public_key_der(user_keys[0].public_key())
    bad_keys = [der + b"\x00", b"garbage", b"\x00" * 1020]
    for bad in bad_keys:
        response = client.post("/register/challenge", json={"public_key": b64e(bad)})
        assert response.status_code == 400
    # Far too large: refused by the request model's length cap before parsing.
    huge = client.post("/register/challenge", json={"public_key": b64e(b"\x00" * 1100)})
    assert huge.status_code == 422


def test_wrong_challenge_response_fails(client, server_paths, user_keys):
    der_b64 = b64e(public_key_der(user_keys[0].public_key()))
    challenge = client.post("/register/challenge", json={"public_key": der_b64}).json()
    body = {
        "invite_code": invite_directly(server_paths, ["Sender"]),
        "username": "user1",
        "password": PASSWORD,
        "public_key": der_b64,
        "challenge_id": challenge["challenge_id"],
        "challenge_response": b64e(b"\x00" * 32),
    }
    response = client.post("/register", json=body)
    assert response.status_code == 400
    assert "possession" in response.json()["detail"]


def test_challenge_is_single_use_and_bound_to_key(app):
    store = app.state.challenges
    challenge_id = store.add(b"c" * 32, "fp-A")
    assert store.consume(challenge_id, b"c" * 32, "fp-B") is False   # other key
    assert store.consume(challenge_id, b"c" * 32, "fp-A") is False   # already consumed
    second_id = store.add(b"d" * 32, "fp-A")
    assert store.consume(second_id, b"d" * 32, "fp-A") is True


def test_challenge_expires(app):
    store = app.state.challenges
    store.ttl = 0
    challenge_id = store.add(b"c" * 32, "fp")
    assert store.consume(challenge_id, b"c" * 32, "fp") is False


# ---------------------------------------------------------------------------
# Login and JWT
# ---------------------------------------------------------------------------

def test_login_same_error_for_unknown_user_and_wrong_password(client, server_paths, user_keys):
    register_raw(client, user_keys[0], invite_directly(server_paths, ["Sender"]), "alice")
    unknown = client.post("/login", json={"username": "nobody", "password": PASSWORD})
    wrong = client.post("/login", json={"username": "alice", "password": "wrong-password-123"})
    assert unknown.status_code == 401
    assert wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_deactivated_user_cannot_login(client, server_paths, user_keys):
    register_raw(client, user_keys[0], invite_directly(server_paths, ["Sender"]), "alice")
    conn = db.connect(server_paths.db)
    conn.execute("UPDATE users SET active = 0 WHERE username = 'alice'")
    conn.close()
    response = client.post("/login", json={"username": "alice", "password": PASSWORD})
    assert response.status_code == 401


def test_login_token_carries_only_user_id(client, app, server_paths, user_keys):
    register_raw(client, user_keys[0], invite_directly(server_paths, ["Sender"]), "alice")
    token = client.post("/login", json={"username": "alice", "password": PASSWORD}).json()["token"]
    claims = jwt.decode(token, app.state.jwt_secret, algorithms=["HS256"])
    assert sorted(claims) == ["exp", "iat", "sub"]  # sorted() of a dict gives its sorted keys
    assert auth.decode_session_token(token, app.state.jwt_secret) == int(claims["sub"])


def test_jwt_rejects_tampering_none_alg_and_expiry():
    secret = b"s" * 32
    good = auth.create_session_token(7, secret, 45)
    assert auth.decode_session_token(good, secret) == 7

    with pytest.raises(jwt.InvalidTokenError):
        auth.decode_session_token(good, b"x" * 32)          # wrong secret

    now = int(time.time())
    unsigned = jwt.encode({"sub": "7", "iat": now, "exp": now + 60}, None, algorithm="none")
    with pytest.raises(jwt.InvalidTokenError):
        auth.decode_session_token(unsigned, secret)        # alg=none

    expired = auth.create_session_token(7, secret, -2)     # beyond the 30 s skew leeway
    with pytest.raises(jwt.InvalidTokenError):
        auth.decode_session_token(expired, secret)

    no_exp = jwt.encode({"sub": "7", "iat": now}, secret, algorithm="HS256")
    with pytest.raises(jwt.InvalidTokenError):
        auth.decode_session_token(no_exp, secret)          # exp missing


def test_passwords_stored_as_argon2(client, server_paths, user_keys):
    register_raw(client, user_keys[0], invite_directly(server_paths, ["Sender"]), "alice")
    conn = db.connect(server_paths.db)
    stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    conn.close()
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_sliding_window_limiter():
    limiter = SlidingWindowLimiter(limit=2, window=60)
    assert limiter.allow("ip", now=0)
    assert limiter.allow("ip", now=1)
    assert not limiter.allow("ip", now=2)       # third request within 60 s
    assert limiter.allow("other-ip", now=2)     # limits are per IP
    assert limiter.allow("ip", now=61)          # first event slid out of the window


def test_login_rate_limited(server_paths):
    app = create_app(server_paths.data_dir)     # default config: limits enabled
    client = TestClient(app)
    statuses = []
    for _ in range(11):
        response = client.post("/login", json={"username": "nobody", "password": "x" * 12})
        statuses.append(response.status_code)
    # The first 10 are answered normally (wrong login), the 11th is blocked.
    for position in range(10):
        assert statuses[position] == 401
    assert statuses[10] == 429
