"""configure, register, login.

These functions take already-collected secrets as arguments; prompting is
done in client/__main__.py. That keeps them easy to test.
"""

import re
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from whisperchain.client.api import ApiClient
from whisperchain.client.errors import ApiError, ClientError
from whisperchain.client.store import ClientStore
from whisperchain.common import constants as C
from whisperchain.common.encoding import b64d, b64e
from whisperchain.common.fingerprint import fingerprint, public_key_der


def generate_user_key():
    """New RSA-3072 key pair, generated locally. The private half never leaves this machine."""
    return rsa.generate_private_key(public_exponent=C.RSA_PUBLIC_EXPONENT, key_size=C.USER_KEY_BITS)


def configure(store: ClientStore, server_url: str | None, ca_cert: str | None,
              send_delay: tuple[float, float] | None = None) -> dict:
    config = store.load_config()
    if send_delay is not None:
        low, high = send_delay
        if low < 0 or high < low:
            raise ClientError("send delay must satisfy 0 <= MIN <= MAX")
        config["send_delay_min"], config["send_delay_max"] = low, high
    if server_url:
        if not server_url.startswith(("https://", "http://")):
            raise ClientError("server URL must start with https://")
        config["server_url"] = server_url.rstrip("/")
    if ca_cert:
        path = Path(ca_cert).expanduser().resolve()
        if not path.is_file():
            raise ClientError(f"CA certificate not found: {path}")
        config["ca_cert"] = str(path)
    store.save_config(config)
    return config


def _check_new_secrets(username: str, password: str, passphrase: str) -> None:
    if not re.fullmatch(C.USERNAME_PATTERN, username):
        raise ClientError("username must be 3-32 characters: letters, digits, '_', '.', '-'")
    if len(password) < C.MIN_PASSWORD_LENGTH:
        raise ClientError(f"password must be at least {C.MIN_PASSWORD_LENGTH} characters")
    if len(passphrase) < C.MIN_PASSWORD_LENGTH:
        raise ClientError(f"key passphrase must be at least {C.MIN_PASSWORD_LENGTH} characters")
    # The password goes to the server; the passphrase must not. If they were
    # the same, the server (which sees the password at login) could unlock
    # a stolen private-key file.
    if password == passphrase:
        raise ClientError("the key passphrase must be different from the account password")


def ensure_can_register(store: ClientStore) -> None:
    """Never overwrite an existing key: losing it would mean losing an inbox."""
    if store.load_identity() is not None or store.has_private_key():
        raise ClientError(
            "this config directory already holds a key; use a different --config-dir "
            "(if an earlier registration actually succeeded, just run `login`)"
        )


def register(
    store: ClientStore,
    api: ApiClient,
    invite_code: str,
    username: str,
    password: str,
    passphrase: str,
    private_key=None,
) -> dict:
    """Register a new account. `private_key` is normally left as None so a
    new key is generated; tests pass a ready-made key because generating
    RSA-3072 keys is slow."""
    ensure_can_register(store)
    _check_new_secrets(username, password, passphrase)

    # 1. Generate the key and save it (encrypted) BEFORE talking to the server.
    #    If the server registers us but the reply is lost, we still have the key.
    if private_key is None:
        private_key = generate_user_key()
    store.save_private_key(private_key, passphrase)
    der = public_key_der(private_key.public_key())
    local_fp = fingerprint(der)

    try:
        # 2. Proof of possession: decrypt the server's challenge with our key.
        challenge = api.register_challenge(b64e(der))
        oaep = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        )
        try:
            answer = private_key.decrypt(b64d(challenge["encrypted_challenge"]), oaep)
        except ValueError:
            raise ClientError("server sent an invalid challenge") from None

        # 3. Register. Note: no role field; roles come only from the invite.
        result = api.register({
            "invite_code": invite_code,
            "username": username,
            "password": password,
            "public_key": b64e(der),
            "challenge_id": challenge["challenge_id"],
            "challenge_response": b64e(answer),
        })
    except ApiError as exc:
        if exc.definitive:
            # The server refused (4xx), so nothing was registered: the key is useless.
            store.delete_private_key()
        # On a network error or 5xx the outcome is unknown, so we keep the key.
        raise

    # The server computes the fingerprint itself; it must match ours.
    if result["fingerprint"] != local_fp:
        raise ClientError("server reported a different key fingerprint; do not use this server")

    store.save_identity({"username": username, "key_id": result["key_id"], "fingerprint": local_fp})
    return result


def login(store: ClientStore, api: ApiClient, username: str, password: str) -> dict:
    result = api.login(username, password)
    store.save_session({"username": username, "token": result["token"], "roles": result["roles"]})
    return result
