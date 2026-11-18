"""Shared test helpers and pytest fixtures.

A "fixture" is a function pytest runs for you: when a test function has a
parameter with the same name as a fixture (e.g. `client`), pytest calls the
fixture and passes its result in. scope="session" means "make it only once
for the whole test run"; scope="module" means once per test file.
"""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from whisperchain.client.api import ApiClient
from whisperchain.client.commands import keys, messages
from whisperchain.client.commands import tokens as token_cmd
from whisperchain.client.store import ClientStore
from whisperchain.common.encoding import b64d, b64e
from whisperchain.common.envelope import build_envelope
from whisperchain.common.fingerprint import public_key_der
from whisperchain.server import db
from whisperchain.server.app import create_app
from whisperchain.server.initialize import create_admin, initialize_data_dir
from whisperchain.server.invites import create_invite

PASSWORD = "correct-horse-battery"
PASSPHRASE = "a-different-key-passphrase"
ADMIN_PASSWORD = "admin-password-123"

OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def make_client_factory(app):
    """ApiClient needs a FUNCTION that creates a new HTTP client each time it
    is called. This returns such a function for the in-process test app."""
    def factory():
        return TestClient(app)
    return factory


def api_client(app, token=None) -> ApiClient:
    """A client-side ApiClient that talks to the in-process app (no network)."""
    return ApiClient(make_client_factory(app), token=token)


def auth_header(token) -> dict:
    """The HTTP header that carries a session token (empty if no token)."""
    if token is None:
        return {}
    return {"Authorization": f"Bearer {token}"}


def invite_directly(paths, roles, expiry_days=7) -> str:
    """Create an invite straight in the database (skipping the Admin route)."""
    conn = db.connect(paths.db)
    try:
        with db.write_transaction(conn):
            code, _expires = create_invite(conn, roles, expiry_days)
    finally:
        conn.close()
    return code


def read_audit_rows(paths) -> list:
    """Every audit entry as a tuple (action, role, detail), in order."""
    conn = db.connect(paths.db)
    try:
        rows = []
        for row in conn.execute("SELECT action, role, detail FROM audit_log ORDER BY seq"):
            rows.append((row["action"], row["role"], row["detail"]))
        return rows
    finally:
        conn.close()


def count_action(rows, action: str) -> int:
    """How many audit rows (from read_audit_rows) have this action."""
    count = 0
    for row in rows:
        if row[0] == action:
            count = count + 1
    return count


def login_token(client, username, password=PASSWORD) -> str:
    response = client.post("/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def register_raw(client, private_key, invite, username, password=PASSWORD, extra_fields=None):
    """Register through the HTTP API directly (challenge + register).

    extra_fields: additional JSON fields to put in the request (a test uses
    this to try sneaking in a "roles" field).
    """
    der_b64 = b64e(public_key_der(private_key.public_key()))
    challenge = client.post("/register/challenge", json={"public_key": der_b64}).json()
    answer = private_key.decrypt(b64d(challenge["encrypted_challenge"]), OAEP)
    body = {
        "invite_code": invite,
        "username": username,
        "password": password,
        "public_key": der_b64,
        "challenge_id": challenge["challenge_id"],
        "challenge_response": b64e(answer),
    }
    if extra_fields is not None:
        for name in extra_fields:
            body[name] = extra_fields[name]
    return client.post("/register", json=body)


# Confirmation callbacks for client functions that ask "are you sure?".
# Both kinds of question pass two values (e.g. old and new fingerprint, or
# moderator names and skipped names); these answers ignore them.
def always_yes(first, second):
    return True


def always_no(first, second):
    return False


# ---------------------------------------------------------------------------
# Basic fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def user_keys():
    """RSA-3072 keys are slow to make, so generate six once per test run."""
    keys_list = []
    for _ in range(6):
        keys_list.append(rsa.generate_private_key(public_exponent=65537, key_size=3072))
    return keys_list


@pytest.fixture
def server_paths(tmp_path):
    """A freshly initialized server data directory (no TLS: tests use no sockets)."""
    return initialize_data_dir(tmp_path / "server_data", make_tls=False)


@pytest.fixture
def app(server_paths):
    return create_app(server_paths.data_dir, {"rate_limit_enabled": False})


@pytest.fixture
def client(app):
    # `yield` in a fixture: the test runs at this point, and the code after
    # it (closing the client at the end of the `with`) runs afterwards.
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# A multi-user "world": one Admin plus one account per role set.
# ---------------------------------------------------------------------------

# The role set each test account holds. The account at position i in this
# list uses user_keys[i] as its private key.
ACCOUNTS = {
    "sender": ["Sender"],
    "recipient": ["Recipient"],
    "moderator": ["Moderator"],
    "both": ["Recipient", "Sender"],
    "victim": ["Sender"],   # target of admin actions
}

def _key_index() -> dict:
    """Which user_keys entry each account owns: {"sender": 0, "recipient": 1, ...}"""
    index = {}
    position = 0
    for name in ACCOUNTS:
        index[name] = position
        position = position + 1
    return index


KEY_INDEX = _key_index()


def build_world(data_dir, user_keys, app_hook=None, config=None):
    """A server with one Admin and one account per entry in ACCOUNTS.

    Returns a dict with:
      "paths", "app", "client" (a TestClient),
      "ids":    username -> user id, and "<username>_key" -> key id
      "tokens": "admin" / username -> session token ("anonymous" -> None)

    app_hook(app) runs before the first request (e.g. to add test middleware).
    config: extra server settings, e.g. {"alert_flag_rate_min_flags": 99}.
    """
    paths = initialize_data_dir(data_dir, make_tls=False)
    settings = {"rate_limit_enabled": False}
    if config is not None:
        for name in config:
            settings[name] = config[name]
    app = create_app(paths.data_dir, settings)
    if app_hook is not None:
        app_hook(app)
    client = TestClient(app)

    create_admin(paths, "root", ADMIN_PASSWORD)
    ids = {}
    tokens = {"admin": login_token(client, "root", ADMIN_PASSWORD), "anonymous": None}
    for name in ACCOUNTS:
        roles = ACCOUNTS[name]
        private_key = user_keys[KEY_INDEX[name]]
        response = register_raw(client, private_key, invite_directly(paths, roles), name)
        assert response.status_code == 200, response.text
        tokens[name] = login_token(client, name)

    users_response = client.get("/admin/users", headers=auth_header(tokens["admin"]))
    assert users_response.status_code == 200, users_response.text
    for row in users_response.json()["users"]:
        ids[row["username"]] = row["id"]

    # Key ids, as "<name>_key", for routes addressed by key.
    conn = db.connect(paths.db)
    for row in conn.execute("SELECT u.username, k.key_id FROM public_keys k JOIN users u ON u.id = k.user_id"):
        ids[row["username"] + "_key"] = row["key_id"]
    conn.close()
    return {"paths": paths, "app": app, "client": client, "ids": ids, "tokens": tokens}


@pytest.fixture(scope="module")
def world(tmp_path_factory, user_keys):
    """One shared world per test file, for tests that only read."""
    return build_world(tmp_path_factory.mktemp("rbac") / "server_data", user_keys)


@pytest.fixture
def fresh_world(tmp_path, user_keys):
    """A new world for every test, for tests that change state."""
    return build_world(tmp_path / "server_data", user_keys)


# ---------------------------------------------------------------------------
# Messaging setup: a world with round 1 open, "sender" holding a token, and
# client stores (with private keys) for "recipient" and "moderator".
# ---------------------------------------------------------------------------

class Setup:
    def __init__(self, world, tmp_path, user_keys):
        self.w = world
        self.app = world["app"]
        self.tmp_path = tmp_path
        world["client"].post("/admin/rounds/start", headers=auth_header(world["tokens"]["admin"]))
        self.sender = self.make_sender("sender")
        self.recipient = self.store_for("recipient")
        self.recipient.save_private_key(user_keys[KEY_INDEX["recipient"]], PASSPHRASE)
        self.moderator = self.store_for("moderator")
        self.moderator.save_private_key(user_keys[KEY_INDEX["moderator"]], PASSPHRASE)

    def make_sender(self, name):
        """A client store for account `name` holding this round's token and a synced directory."""
        store = self.store_for(name)
        token_cmd.request_token(store, self.api(name))
        keys.sync(store, self.api(name), include_moderators=False)
        return store

    def api(self, who=None):
        """ApiClient logged in as `who` (or not logged in if who is None)."""
        if who is None:
            return api_client(self.app)
        return api_client(self.app, self.w["tokens"][who])

    def store_for(self, name):
        return ClientStore(self.tmp_path / name)

    def send(self, to="recipient", text="hello", api=None, sender=None):
        """Send through the real client code (no random delay)."""
        if sender is None:
            sender = self.sender
        if api is None:
            api = self.api()
        return messages.send(sender, api, to, text, now=True)

    def message_count(self):
        conn = db.connect(self.w["paths"].db)
        try:
            return conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        finally:
            conn.close()

    def audit(self):
        return read_audit_rows(self.w["paths"])

    def raw_body(self, to="recipient", text="raw", round_number=1, key_owner=None, sender=None):
        """A send body built by hand from a sender's token (for server tests).

        key_owner: encrypt to this user's key instead of `to`'s (to test a
        mismatched key).
        """
        if sender is None:
            sender = self.sender
        if key_owner is None:
            key_owner = to
        entry, public_key = keys.trusted_key(sender, key_owner)
        token = sender.load_token(round_number)
        envelope = build_envelope(text, public_key, entry["key_id"], round_number)
        return {"recipient": to, "round": round_number, "envelope": b64e(envelope),
                "t": token["t"], "s": token["s"]}

    def post(self, body):
        return self.w["client"].post("/messages", json=body)
