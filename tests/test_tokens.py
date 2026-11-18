"""Stage 6: blind signatures, rounds, token issuance, unlinkable schema."""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import api_client, auth_header, count_action, make_client_factory, read_audit_rows
from whisperchain.client.api import ApiClient
from whisperchain.client.commands import tokens as token_cmd
from whisperchain.client.errors import ApiError, NetworkError
from whisperchain.client.store import ClientStore
from whisperchain.common import blind
from whisperchain.common.encoding import b64_to_int, b64d, int_to_b64
from whisperchain.server import db

# ---------------------------------------------------------------------------
# Blind-signature arithmetic
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def round_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def key_numbers(key) -> dict:
    """The RSA numbers of a key: n (modulus), e (public exponent), d (private exponent)."""
    public = key.public_key().public_numbers()
    return {"n": public.n, "e": public.e, "d": key.private_numbers().d}


def test_fdh_is_deterministic_and_below_n(round_key):
    n = key_numbers(round_key)["n"]
    t = blind.new_token_secret()
    hashed = blind.fdh(t, n)
    assert blind.fdh(t, n) == hashed               # same input, same output
    assert hashed >= 0
    assert hashed < n
    assert hashed.bit_length() > 2000              # full-domain, not a short 256-bit hash
    assert blind.fdh(blind.new_token_secret(), n) != hashed


def test_blind_unblind_round_trip(round_key):
    numbers = key_numbers(round_key)
    n = numbers["n"]
    e = numbers["e"]
    d = numbers["d"]
    t = blind.new_token_secret()
    m = blind.fdh(t, n)
    blinded, r = blind.blind(m, n, e)
    assert blinded != m                      # the server never sees m
    blind_signature = blind.sign_blinded(blinded, d, n)
    s = blind.unblind(blind_signature, r, n)
    assert s == pow(m, d, n)                 # same as signing m directly
    assert blind.verify_token(t, s, n, e)


def test_verify_rejects_bad_tokens(round_key):
    numbers = key_numbers(round_key)
    n = numbers["n"]
    e = numbers["e"]
    t = blind.new_token_secret()
    s = pow(blind.fdh(t, n), numbers["d"], n)
    assert blind.verify_token(t, s, n, e)                                 # the real token works
    assert not blind.verify_token(blind.new_token_secret(), s, n, e)      # other t
    assert not blind.verify_token(t, s + 1, n, e)                         # other s
    assert not blind.verify_token(t, s + n, n, e)                         # out of range
    assert not blind.verify_token(t, 0, n, e)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = key_numbers(other_key)
    assert not blind.verify_token(t, s, other["n"], other["e"])           # other round's key


def test_sign_blinded_range_check(round_key):
    numbers = key_numbers(round_key)
    n = numbers["n"]
    for bad in [0, n, n + 1, -1]:
        with pytest.raises(ValueError):
            blind.sign_blinded(bad, numbers["d"], n)


def test_blinding_hides_the_message(round_key):
    """Blinding the same m twice gives unrelated values (fresh random r)."""
    numbers = key_numbers(round_key)
    n = numbers["n"]
    m = blind.fdh(blind.new_token_secret(), n)
    first_blinded, _first_r = blind.blind(m, n, numbers["e"])
    second_blinded, _second_r = blind.blind(m, n, numbers["e"])
    assert first_blinded != second_blinded


# ---------------------------------------------------------------------------
# Rounds
# ---------------------------------------------------------------------------


@pytest.fixture
def w(fresh_world):
    return fresh_world


def start_round(world) -> int:
    response = world["client"].post("/admin/rounds/start", headers=auth_header(world["tokens"]["admin"]))
    assert response.status_code == 200, response.text
    return response.json()["round"]


def api(world, who):
    return api_client(world["app"], world["tokens"][who])


def test_no_round_initially(w):
    assert w["client"].get("/round/current").status_code == 404


def test_start_round_closes_previous(w):
    assert start_round(w) == 1
    assert start_round(w) == 2
    current = w["client"].get("/round/current").json()
    assert current["round"] == 2

    conn = db.connect(w["paths"].db)
    statuses = {}
    for row in conn.execute("SELECT round, status FROM rounds"):
        statuses[row["round"]] = row["status"]
    conn.close()
    assert statuses == {1: "closed", 2: "open"}

    assert w["paths"].round_key(1).exists()
    assert w["paths"].round_key(2).exists()
    if os.name != "nt":
        assert w["paths"].round_key(2).stat().st_mode & 0o777 == 0o600


def test_round_key_is_2048_bits(w):
    start_round(w)
    n = b64_to_int(w["client"].get("/round/current").json()["n"])
    assert n.bit_length() == 2048


# ---------------------------------------------------------------------------
# Issuance (server)
# ---------------------------------------------------------------------------


def make_blinded_request(world) -> dict:
    """Do the client's half of the blind-signature protocol by hand.

    Returns a dict with the round number, the round's public key (n, e),
    the token secret t, the blinded value, and the blinding factor r.
    """
    current = world["client"].get("/round/current").json()
    n = b64_to_int(current["n"])
    e = b64_to_int(current["e"])
    t = blind.new_token_secret()
    blinded, r = blind.blind(blind.fdh(t, n), n, e)
    return {"round": current["round"], "n": n, "e": e, "t": t, "blinded": blinded, "r": r}


def issue(world, who, round_number, blinded):
    """POST /tokens/issue as `who`."""
    body = {"round": round_number, "blinded": int_to_b64(blinded)}
    return world["client"].post("/tokens/issue", json=body, headers=auth_header(world["tokens"][who]))


def test_issue_and_verify(w):
    start_round(w)
    request = make_blinded_request(w)
    response = issue(w, "sender", request["round"], request["blinded"])
    assert response.status_code == 200
    blind_signature = b64_to_int(response.json()["blind_signature"])
    s = blind.unblind(blind_signature, request["r"], request["n"])
    assert blind.verify_token(request["t"], s, request["n"], request["e"])

    rows = read_audit_rows(w["paths"])
    last_row = rows[len(rows) - 1]
    assert last_row == ("TOKEN_ISSUED", "Sender", f"round: {request['round']}")


def test_one_token_per_user_per_round(w):
    start_round(w)
    first = make_blinded_request(w)
    assert issue(w, "sender", first["round"], first["blinded"]).status_code == 200
    other = make_blinded_request(w)
    assert issue(w, "sender", first["round"], other["blinded"]).status_code == 409
    # A different Sender is unaffected...
    assert issue(w, "both", first["round"], other["blinded"]).status_code == 200
    # ...and a new round allows a new token.
    start_round(w)
    new = make_blinded_request(w)
    assert issue(w, "sender", new["round"], new["blinded"]).status_code == 200


def test_same_blinded_retry_returns_same_signature(w):
    start_round(w)
    request = make_blinded_request(w)
    first = issue(w, "sender", request["round"], request["blinded"]).json()
    count_before = count_action(read_audit_rows(w["paths"]), "TOKEN_ISSUED")
    second = issue(w, "sender", request["round"], request["blinded"]).json()
    assert first == second
    # Not issued twice: no new TOKEN_ISSUED entry.
    assert count_action(read_audit_rows(w["paths"]), "TOKEN_ISSUED") == count_before


@pytest.mark.parametrize("who", ["recipient", "moderator", "admin"])
def test_non_senders_refused(w, who):
    start_round(w)
    request = make_blinded_request(w)
    assert issue(w, who, request["round"], request["blinded"]).status_code == 403


def test_issue_requires_open_and_matching_round(w):
    assert issue(w, "sender", 1, 5).status_code == 409                       # no round yet
    start_round(w)
    request = make_blinded_request(w)
    assert issue(w, "sender", request["round"] + 1, 5).status_code == 409    # wrong round
    assert issue(w, "sender", request["round"], request["n"]).status_code == 400  # out of range
    assert issue(w, "sender", request["round"], 0).status_code == 400


def test_issued_table_stores_only_blinded_value(w):
    start_round(w)
    request = make_blinded_request(w)
    issue(w, "sender", request["round"], request["blinded"])
    conn = db.connect(w["paths"].db)
    rows = conn.execute("SELECT round, user_id, blinded FROM issued").fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0]["round"] == request["round"]
    assert rows[0]["user_id"] == w["ids"]["sender"]
    assert rows[0]["blinded"] == int_to_b64(request["blinded"])
    assert blind.token_hash(request["t"]) not in str(dict(rows[0]))


# ---------------------------------------------------------------------------
# Schema unjoinability: issued and messages cannot be linked by the database
# ---------------------------------------------------------------------------


def column_names(conn, table) -> list[str]:
    names = []
    for row in conn.execute(f"PRAGMA table_info({table})"):
        names.append(row["name"])
    return names


def foreign_key_targets(conn, table) -> list[str]:
    """Tables that `table` has a foreign key to."""
    targets = []
    for row in conn.execute(f"PRAGMA foreign_key_list({table})"):
        targets.append(row["table"])
    return targets


def test_schema_unjoinability(server_paths):
    conn = db.connect(server_paths.db)
    issued_columns = column_names(conn, "issued")
    message_columns = column_names(conn, "messages")

    # The ONLY column the two tables share is "round".
    shared = []
    for name in issued_columns:
        if name in message_columns:
            shared.append(name)
    assert shared == ["round"]

    # No foreign key in either direction.
    assert "messages" not in foreign_key_targets(conn, "issued")
    assert "issued" not in foreign_key_targets(conn, "messages")

    # No timestamp-like columns in either table.
    for name in issued_columns + message_columns:
        for word in ["time", "date", "_at", "created"]:
            assert word not in name.lower()
    conn.close()


# ---------------------------------------------------------------------------
# Client: token request, pending-file recovery, status
# ---------------------------------------------------------------------------


def test_client_token_request(w, tmp_path):
    start_round(w)
    store = ClientStore(tmp_path / "s")
    assert token_cmd.request_token(store, api(w, "sender"))["status"] == "token received"
    saved = store.load_token(1)
    assert sorted(saved) == ["round", "s", "t"]
    current = w["client"].get("/round/current").json()
    assert blind.verify_token(b64d(saved["t"]), b64_to_int(saved["s"]),
                              b64_to_int(current["n"]), b64_to_int(current["e"]))
    assert store.load_pending(1) is None   # r destroyed
    # Running again is harmless.
    assert "already" in token_cmd.request_token(store, api(w, "sender"))["status"]


class LostResponseApi(ApiClient):
    """An ApiClient whose token request reaches the server, but whose answer
    is "lost": it raises a network error instead of returning it."""

    def issue_token(self, round_number, blinded_b64):
        # Do the real request (the normal ApiClient.issue_token)...
        ApiClient.issue_token(self, round_number, blinded_b64)
        # ...then pretend the connection dropped before we saw the answer.
        raise NetworkError("connection dropped")


def test_pending_file_recovers_lost_response(w, tmp_path):
    start_round(w)
    store = ClientStore(tmp_path / "s")
    lossy = LostResponseApi(make_client_factory(w["app"]), token=w["tokens"]["sender"])
    with pytest.raises(NetworkError):
        token_cmd.request_token(store, lossy)
    assert store.load_pending(1) is not None
    assert store.load_token(1) is None

    # The server already recorded our issuance; re-running sends the same
    # blinded value and gets the same signature back instead of a 409.
    assert token_cmd.request_token(store, api(w, "sender"))["status"] == "token received"
    assert store.load_token(1) is not None
    assert store.load_pending(1) is None


def test_token_status_marks_closed_rounds(w, tmp_path):
    start_round(w)
    store = ClientStore(tmp_path / "s")
    token_cmd.request_token(store, api(w, "sender"))
    status = token_cmd.token_status(store, api(w, "sender"))
    assert status["tokens"] == [{"round": 1, "usable": True}]
    start_round(w)
    status = token_cmd.token_status(store, api(w, "sender"))
    assert status["open_round"] == 2
    assert status["tokens"] == [{"round": 1, "usable": False}]


def test_client_refused_for_non_sender(w, tmp_path):
    start_round(w)
    with pytest.raises(ApiError) as exc:
        token_cmd.request_token(ClientStore(tmp_path / "r"), api(w, "recipient"))
    assert exc.value.status == 403


def test_refused_second_request_leaves_no_pending_file(w, tmp_path):
    """After spending this round's token, asking again is refused cleanly."""
    start_round(w)
    store = ClientStore(tmp_path / "s")
    token_cmd.request_token(store, api(w, "sender"))
    store.delete_token(1)                       # as if the token had been spent
    with pytest.raises(ApiError) as exc:
        token_cmd.request_token(store, api(w, "sender"))
    assert exc.value.status == 409
    tokens, pending = store.list_token_rounds()
    assert tokens == []
    assert pending == []
