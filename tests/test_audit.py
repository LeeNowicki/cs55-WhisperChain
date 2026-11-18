"""Stage 4: audit log chain, signatures, tamper detection, checkpoint, privacy."""

import pytest

from conftest import ACCOUNTS, PASSWORD, api_client, auth_header, invite_directly, register_raw
from whisperchain.client.commands import audit as audit_cmd
from whisperchain.client.errors import ClientError
from whisperchain.client.store import ClientStore
from whisperchain.common.audit_chain import compute_entry_hash
from whisperchain.server import db


@pytest.fixture
def w(fresh_world):
    """Short name for a fresh world (see conftest.build_world)."""
    return fresh_world


def auditor_api(world, who="moderator"):
    return api_client(world["app"], world["tokens"][who])


def actions(world) -> list[str]:
    """The action of every audit entry, in order."""
    conn = db.connect(world["paths"].db)
    try:
        result = []
        for row in conn.execute("SELECT action FROM audit_log ORDER BY seq"):
            result.append(row["action"])
        return result
    finally:
        conn.close()


def raw_sql(world, statements: list[str]):
    """Run SQL directly on the database file, as an attacker with file access could."""
    conn = db.connect(world["paths"].db)
    try:
        for statement in statements:
            conn.execute(statement)
    finally:
        conn.close()


def drop_triggers(world):
    raw_sql(world, ["DROP TRIGGER audit_log_no_update", "DROP TRIGGER audit_log_no_delete"])


# ---------------------------------------------------------------------------
# Events are written by every route built so far
# ---------------------------------------------------------------------------

def test_events_recorded(w):
    client = w["client"]
    admin = auth_header(w["tokens"]["admin"])
    client.post("/admin/invites", json={"roles": ["Sender"]}, headers=admin)
    client.post(f"/admin/users/{w['ids']['victim']}/roles", json={"roles": ["Recipient"]}, headers=admin)
    client.post(f"/admin/users/{w['ids']['victim']}/deactivate", headers=admin)
    client.get("/admin/users", headers=auth_header(w["tokens"]["sender"]))      # 403
    client.get("/audit", headers=auth_header(w["tokens"]["moderator"]))

    log = actions(w)
    # The "moderator" account's registration triggered one MODERATOR_GRANTED alert.
    assert log.count("ALERT") == 1

    # Without the alert: init-admin, then USER_REGISTERED + KEY_REGISTERED per account.
    without_alerts = []
    for action in log:
        if action != "ALERT":
            without_alerts.append(action)
    expected_start = ["USER_REGISTERED"]
    for _account in ACCOUNTS:
        expected_start.append("USER_REGISTERED")
        expected_start.append("KEY_REGISTERED")
    assert without_alerts[0:len(expected_start)] == expected_start

    # The last five entries, in order.
    last_five = log[len(log) - 5:]
    assert last_five == ["INVITE_CREATED", "ROLES_CHANGED", "USER_DEACTIVATED", "ACCESS_DENIED", "AUDIT_VIEWED"]


def test_logins_and_401s_are_not_logged(w):
    before = actions(w)
    w["client"].post("/login", json={"username": "sender", "password": PASSWORD})
    w["client"].post("/login", json={"username": "sender", "password": "wrong-password-1"})
    w["client"].get("/audit")                                   # no token: 401
    w["client"].get("/audit", headers=auth_header("garbage"))   # bad token: 401
    assert actions(w) == before


def test_access_denied_records_roles_and_permission_only(w):
    w["client"].post("/admin/invites", json={"roles": ["Sender"]}, headers=auth_header(w["tokens"]["both"]))
    conn = db.connect(w["paths"].db)
    row = conn.execute("SELECT role, detail FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    conn.close()
    assert row["role"] == "Recipient,Sender"
    assert row["detail"] == "permission: invite:create"


def test_failed_operation_leaves_no_audit_entry(w, user_keys):
    """Atomic audit: a registration that fails (taken username) logs nothing."""
    before = actions(w)
    invite = invite_directly(w["paths"], ["Sender"])
    response = register_raw(w["client"], user_keys[0], invite, "sender")
    assert response.status_code == 409
    assert actions(w) == before


def test_audit_entry_rolls_back_with_its_transaction(w):
    conn = db.connect(w["paths"].db)
    before = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    with pytest.raises(RuntimeError):
        with db.write_transaction(conn):
            w["app"].state.audit.append_audit(conn, "INVITE_CREATED", "Admin", "roles: Sender")
            raise RuntimeError("operation failed after auditing")
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == before
    conn.close()


def test_append_outside_transaction_refused(w):
    conn = db.connect(w["paths"].db)
    with pytest.raises(RuntimeError):
        w["app"].state.audit.append_audit(conn, "ALERT", "System", "rule: X")
    conn.close()


# ---------------------------------------------------------------------------
# Privacy: no identities in the log
# ---------------------------------------------------------------------------

IDENTIFYING_DETAILS = ["user: alice", "alice", "id: 3", "token: abc", "1.2.3.4", "roles: Sender, alice"]


@pytest.mark.parametrize("detail", IDENTIFYING_DETAILS)
def test_append_rejects_identifying_detail(w, detail):
    conn = db.connect(w["paths"].db)
    with pytest.raises(ValueError):
        with db.write_transaction(conn):
            w["app"].state.audit.append_audit(conn, "ALERT", "System", detail)
    conn.close()


def contains_a_digit(text: str) -> bool:
    for character in text:
        if character.isdigit():
            return True
    return False


def test_log_contains_no_identities(w):
    client = w["client"]
    admin = auth_header(w["tokens"]["admin"])
    invite = client.post("/admin/invites", json={"roles": ["Sender"]}, headers=admin).json()["invite_code"]
    client.post(f"/admin/users/{w['ids']['victim']}/deactivate", headers=admin)
    client.get("/admin/users", headers=auth_header(w["tokens"]["sender"]))

    # Everything that must never appear: usernames, the invite code, the
    # password, and every session token.
    forbidden = []
    for username in ACCOUNTS:
        forbidden.append(username)
    forbidden.append("root")
    forbidden.append(invite)
    forbidden.append(PASSWORD)
    for name in w["tokens"]:
        if w["tokens"][name] is not None:
            forbidden.append(w["tokens"][name])

    conn = db.connect(w["paths"].db)
    rows = conn.execute("SELECT action, role, detail FROM audit_log").fetchall()
    conn.close()
    for row in rows:
        text = row["action"] + " " + row["role"] + " " + row["detail"]
        for secret in forbidden:
            assert secret not in text, (secret, text)
        # The only numbers allowed in detail are round numbers.
        if contains_a_digit(row["detail"]):
            assert row["detail"].startswith("round: ")


# ---------------------------------------------------------------------------
# Client-side verification
# ---------------------------------------------------------------------------

def test_chain_verifies_and_checkpoint_saved(w, tmp_path):
    store = ClientStore(tmp_path / "mod")
    result = audit_cmd.verify(store, auditor_api(w))
    assert result["entries"] == len(actions(w))
    assert store.load_audit_checkpoint()["seq"] == result["checkpoint_seq"]
    assert store.load_audit_pin() is not None
    # Verifying again (log has grown by AUDIT_VIEWED entries) still passes.
    audit_cmd.verify(store, auditor_api(w))


def test_admin_can_also_verify(w, tmp_path):
    audit_cmd.verify(ClientStore(tmp_path / "adm"), auditor_api(w, "admin"))


def test_triggers_block_update_and_delete(w):
    conn = db.connect(w["paths"].db)
    with pytest.raises(Exception, match="append-only"):
        conn.execute("UPDATE audit_log SET detail = 'x' WHERE seq = 2")
    with pytest.raises(Exception, match="append-only"):
        conn.execute("DELETE FROM audit_log WHERE seq = 2")
    conn.close()


def test_tampered_row_detected(w, tmp_path):
    drop_triggers(w)
    raw_sql(w, ["UPDATE audit_log SET detail = 'roles: Admin' WHERE seq = 3"])
    with pytest.raises(audit_cmd.AuditVerificationError) as exc:
        audit_cmd.verify(ClientStore(tmp_path / "m"), auditor_api(w))
    assert exc.value.seq == 3
    assert "modified" in exc.value.reason


def test_tamper_with_recomputed_hash_caught_by_signature(w, tmp_path):
    """An attacker who edits a row AND recomputes its hash still lacks the signing key."""
    drop_triggers(w)
    conn = db.connect(w["paths"].db)
    row = conn.execute("SELECT * FROM audit_log WHERE seq = 3").fetchone()
    new_hash = compute_entry_hash(3, row["timestamp"], row["action"], row["role"], "roles: Admin", row["prev_hash"])
    conn.execute("UPDATE audit_log SET detail = 'roles: Admin', entry_hash = ? WHERE seq = 3", (new_hash,))
    conn.close()
    with pytest.raises(audit_cmd.AuditVerificationError) as exc:
        audit_cmd.verify(ClientStore(tmp_path / "m"), auditor_api(w))
    assert exc.value.seq == 3
    assert "signature" in exc.value.reason


def test_deleted_row_detected(w, tmp_path):
    drop_triggers(w)
    raw_sql(w, ["DELETE FROM audit_log WHERE seq = 4"])
    with pytest.raises(audit_cmd.AuditVerificationError) as exc:
        audit_cmd.verify(ClientStore(tmp_path / "m"), auditor_api(w))
    assert exc.value.seq == 4


def test_truncation_caught_by_checkpoint(w, tmp_path):
    store = ClientStore(tmp_path / "m")
    audit_cmd.verify(store, auditor_api(w))
    checkpoint = store.load_audit_checkpoint()

    # Cut entries off the END: what remains is still a perfectly valid chain...
    drop_triggers(w)
    cut_from = checkpoint["seq"] - 2
    raw_sql(w, [f"DELETE FROM audit_log WHERE seq >= {cut_from}"])

    # ...so a client with no checkpoint is fooled,
    audit_cmd.verify(ClientStore(tmp_path / "fresh"), auditor_api(w))
    # but our checkpoint is not, and it is not moved forward.
    with pytest.raises(audit_cmd.AuditVerificationError) as exc:
        audit_cmd.verify(store, auditor_api(w))
    assert "truncated" in exc.value.reason
    assert store.load_audit_checkpoint() == checkpoint


def test_changed_audit_key_refused(w, tmp_path):
    store = ClientStore(tmp_path / "m")
    store.save_audit_pin("A" * 44)  # some other key
    with pytest.raises(ClientError, match="CHANGED"):
        audit_cmd.verify(store, auditor_api(w))


def test_show_and_alerts(w):
    entries = audit_cmd.show(auditor_api(w), tail=2)
    assert len(entries) == 2
    assert entries[1]["action"] == "AUDIT_VIEWED"
    # The only alert so far: registering the "moderator" account.
    alert_entries = audit_cmd.alerts(auditor_api(w))
    assert len(alert_entries) == 1
    assert alert_entries[0]["detail"] == "rule: MODERATOR_GRANTED"


def test_public_key_is_public(w):
    response = w["client"].get("/audit/public-key")
    assert response.status_code == 200
    assert response.json()["algorithm"] == "Ed25519"


def test_audit_paging(w):
    headers = auth_header(w["tokens"]["moderator"])
    page = w["client"].get("/audit?after_seq=2&limit=3", headers=headers).json()["entries"]
    seq_numbers = []
    for entry in page:
        seq_numbers.append(entry["seq"])
    assert seq_numbers == [3, 4, 5]
    assert w["client"].get("/audit?limit=501", headers=headers).status_code == 422
