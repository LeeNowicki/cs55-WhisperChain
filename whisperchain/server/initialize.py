"""One-time server setup: data directory, secrets, TLS cert, first Admin.

These functions are called by `python -m whisperchain.server init` and
`init-admin`. Tests call them directly with a temporary directory.
"""

import ipaddress
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from whisperchain.common import constants as C
from whisperchain.common.files import write_private_file
from whisperchain.server import auth, db
from whisperchain.server.audit import AuditLog, load_signing_key, roles_detail
from whisperchain.server.config import ServerPaths

TLS_KEY_BITS = 3072
TLS_VALID_DAYS = 365


def initialize_data_dir(data_dir: Path, make_tls: bool = True) -> ServerPaths:
    """Create the database, JWT secret, audit signing key and TLS cert.

    Refuses to run on an existing installation: re-running init would replace
    the secrets, invalidating every session and the audit log's signatures.
    make_tls=False is used by tests, which never open a real socket.
    """
    paths = ServerPaths(Path(data_dir))
    if paths.db.exists():
        raise FileExistsError(f"{paths.db} already exists; refusing to re-initialize")

    paths.data_dir.mkdir(parents=True, exist_ok=True)
    paths.secrets_dir.mkdir(exist_ok=True)
    paths.keys_dir.mkdir(exist_ok=True)

    # HS256 signing secret for session JWTs: 32 random bytes from the OS CSPRNG.
    write_private_file(paths.jwt_secret, secrets.token_bytes(C.JWT_SECRET_BYTES))

    # Ed25519 key that signs every audit entry, so tampering is detectable.
    audit_key = ed25519.Ed25519PrivateKey.generate()
    write_private_file(
        paths.audit_key,
        audit_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            # Unencrypted so the server can start unattended; the file is
            # protected by file permissions instead.
            serialization.NoEncryption(),
        ),
    )

    if make_tls:
        generate_tls_cert(paths)

    # Create the schema last, so the DB's existence means "init finished".
    conn = db.connect(paths.db)
    try:
        db.create_schema(conn)
    finally:
        conn.close()
    return paths


def generate_tls_cert(paths: ServerPaths) -> None:
    """Self-signed certificate for localhost / 127.0.0.1.

    The CLI pins this exact certificate (it is the only CA the client trusts),
    so no public certificate authority is involved.
    """
    paths.tls_dir.mkdir(exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=TLS_KEY_BITS)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WhisperChain+ localhost")])
    now = datetime.now(timezone.utc)
    public_key = key.public_key()

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed: issuer == subject
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))  # tolerate small clock skew
        .not_valid_after(now + timedelta(days=TLS_VALID_DAYS))
        # Hostname checking uses the SAN, not the CN, so list both names here.
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        # ca=True lets Python's ssl module accept this cert as its own trust
        # anchor when the client loads it with cafile=cert.pem.
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,  # needed because this cert is also a CA
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        # Key identifiers are required by Python 3.13+'s strict X.509 checks.
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    write_private_file(
        paths.tls_key,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    # The certificate is public; it is what clients copy and pin.
    paths.tls_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def create_admin(paths: ServerPaths, username: str, password: str) -> int:
    """Create an Admin account. Only reachable from the server host.

    There is no network route that can create an Admin, so taking over the
    admin role requires access to the server machine itself.
    """
    auth.validate_username(username)
    auth.validate_password(password)
    password_hash = auth.hash_password(password)  # slow; do it before locking

    conn = db.connect(paths.db)
    try:
        with db.write_transaction(conn):
            try:
                cur = conn.execute(
                    "INSERT INTO users (username, password_hash, active, created_at) "
                    "VALUES (?, ?, 1, ?)",
                    (username, password_hash, db.now_iso()),
                )
            except sqlite3.IntegrityError:
                raise ValueError("that username is already taken") from None
            user_id = cur.lastrowid
            # Admin is exclusive: an Admin account holds no other role.
            conn.execute(
                "INSERT INTO user_roles (user_id, role) VALUES (?, ?)",
                (user_id, C.ROLE_ADMIN),
            )
            audit = AuditLog(load_signing_key(paths.audit_key))
            audit.append_audit(conn, "USER_REGISTERED", "System", roles_detail([C.ROLE_ADMIN]))
        return user_id
    finally:
        conn.close()
