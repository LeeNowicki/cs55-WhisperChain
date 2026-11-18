"""Stage 1: app starts, schema is created, audit log is append-only."""

import os
import sqlite3

import pytest
from cryptography import x509

from whisperchain.common import constants as C
from whisperchain.common.encoding import b64_to_int, b64d, b64e, canonical_json, int_to_b64
from whisperchain.server import db
from whisperchain.server.app import create_app
from whisperchain.server.initialize import create_admin, initialize_data_dir

EXPECTED_TABLES = {
    "users", "user_roles", "invites", "public_keys", "rounds", "issued", "messages",
    "flags", "flag_keys", "frozen_tokens", "alert_state", "audit_log",
}


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_app_requires_init(tmp_path):
    with pytest.raises(RuntimeError):
        create_app(tmp_path / "nothing_here")


def test_init_refuses_to_run_twice(server_paths):
    with pytest.raises(FileExistsError):
        initialize_data_dir(server_paths.data_dir, make_tls=False)


def test_schema_creates_all_tables(server_paths):
    conn = db.connect(server_paths.db)
    names = []
    for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        names.append(row["name"])
    conn.close()
    for table in EXPECTED_TABLES:
        assert table in names


def test_audit_triggers_exist(server_paths):
    conn = db.connect(server_paths.db)
    triggers = []
    for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'"):
        triggers.append(row["name"])
    conn.close()
    assert "audit_log_no_update" in triggers
    assert "audit_log_no_delete" in triggers


def _insert_fake_audit_row(conn):
    conn.execute(
        "INSERT INTO audit_log (seq, timestamp, action, role, detail, prev_hash, entry_hash, signature) "
        "VALUES (1, 't', 'TEST', 'System', '', ?, 'h', 's')",
        (C.AUDIT_GENESIS_HASH,),
    )


def test_audit_log_blocks_update_and_delete(server_paths):
    conn = db.connect(server_paths.db)
    _insert_fake_audit_row(conn)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE audit_log SET action='EDITED' WHERE seq=1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM audit_log WHERE seq=1")
    assert conn.execute("SELECT action FROM audit_log WHERE seq=1").fetchone()[0] == "TEST"
    conn.close()


def test_write_transaction_rolls_back_on_error(server_paths):
    conn = db.connect(server_paths.db)
    with pytest.raises(RuntimeError):
        with db.write_transaction(conn):
            _insert_fake_audit_row(conn)
            raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0
    conn.close()


def test_foreign_keys_enforced(server_paths):
    conn = db.connect(server_paths.db)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO user_roles (user_id, role) VALUES (999, 'Sender')")
    conn.close()


def test_secrets_created_private(server_paths):
    assert server_paths.jwt_secret.stat().st_size == C.JWT_SECRET_BYTES
    assert server_paths.audit_key.exists()
    if os.name != "nt":
        assert server_paths.jwt_secret.stat().st_mode & 0o777 == 0o600
        assert server_paths.audit_key.stat().st_mode & 0o777 == 0o600


def test_tls_cert_has_san_and_ca(tmp_path):
    paths = initialize_data_dir(tmp_path / "with_tls", make_tls=True)
    cert = x509.load_pem_x509_certificate(paths.tls_cert.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in san.get_values_for_type(x509.DNSName)
    ip_addresses = san.get_values_for_type(x509.IPAddress)
    assert len(ip_addresses) == 1
    assert str(ip_addresses[0]) == "127.0.0.1"
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True


def test_create_admin(server_paths):
    user_id = create_admin(server_paths, "root_admin", "a-long-password-123")
    conn = db.connect(server_paths.db)
    roles = []
    for row in conn.execute("SELECT role FROM user_roles WHERE user_id=?", (user_id,)):
        roles.append(row["role"])
    stored = conn.execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()[0]
    conn.close()
    assert roles == ["Admin"]
    assert stored.startswith("$argon2id$")  # hashed, never stored in clear


def test_create_admin_rejects_short_password_and_duplicates(server_paths):
    with pytest.raises(ValueError):
        create_admin(server_paths, "root_admin", "short")
    create_admin(server_paths, "root_admin", "a-long-password-123")
    with pytest.raises(ValueError):
        create_admin(server_paths, "root_admin", "another-long-password")


def test_envelope_size_constant():
    assert C.ENVELOPE_BYTES == 1 + 16 + 384 + 12 + 1040 == 1453


def test_encoding_round_trips():
    assert b64d(b64e(b"\x00\xffhello")) == b"\x00\xffhello"
    big = 2**2047 + 12345
    assert b64_to_int(int_to_b64(big)) == big
    assert b64_to_int(int_to_b64(0)) == 0
    with pytest.raises(ValueError):
        b64d("not base64 !!")


def test_canonical_json_is_deterministic():
    assert canonical_json({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'
    assert canonical_json({"a": "é"}) == b'{"a":"\\u00e9"}'
