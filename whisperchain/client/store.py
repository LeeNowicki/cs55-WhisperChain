"""Local client state, all inside one config directory.

Every file is written private to the user (0o600 on Linux/macOS). The
private key is additionally encrypted with the user's key passphrase.
"""

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from whisperchain.client.errors import ClientError
from whisperchain.common.files import make_private_dir, write_private_file


def default_config_dir() -> Path:
    return Path.home() / ".whisperchain"


class ClientStore:
    def __init__(self, config_dir: Path):
        self.dir = Path(config_dir)

    # --- file locations ------------------------------------------------------
    @property
    def config_path(self) -> Path:
        return self.dir / "config.json"

    @property
    def private_key_path(self) -> Path:
        return self.dir / "private_key.pem"

    @property
    def identity_path(self) -> Path:
        return self.dir / "identity.json"

    @property
    def session_path(self) -> Path:
        return self.dir / "session.json"

    @property
    def directory_cache_path(self) -> Path:
        return self.dir / "directory_cache.json"

    @property
    def pins_path(self) -> Path:
        return self.dir / "pins.json"

    @property
    def tokens_dir(self) -> Path:
        return self.dir / "tokens"

    def token_path(self, round_number: int) -> Path:
        return self.tokens_dir / f"{round_number}.json"

    def pending_path(self, round_number: int) -> Path:
        return self.tokens_dir / f"pending_{round_number}.json"

    @property
    def outbox_path(self) -> Path:
        return self.dir / "outbox.json"

    @property
    def audit_pubkey_pin_path(self) -> Path:
        return self.dir / "audit_pubkey.pin"

    @property
    def audit_checkpoint_path(self) -> Path:
        return self.dir / "audit_checkpoint.json"

    def ensure_dir(self) -> None:
        make_private_dir(self.dir)

    # --- generic JSON helpers ---------------------------------------------------
    def _read_json(self, path: Path, default=None):
        if not path.exists():
            return default
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def _write_json(self, path: Path, obj) -> None:
        self.ensure_dir()
        data = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8")
        write_private_file(path, data, overwrite=True)

    # --- config.json --------------------------------------------------------------
    def load_config(self) -> dict:
        return self._read_json(self.config_path, default={})

    def save_config(self, config: dict) -> None:
        self._write_json(self.config_path, config)

    # --- identity.json (username, key_id, fingerprint) ----------------------------
    def load_identity(self) -> dict | None:
        return self._read_json(self.identity_path)

    def save_identity(self, identity: dict) -> None:
        self._write_json(self.identity_path, identity)

    # --- session.json (the JWT) ---------------------------------------------------
    def load_session(self) -> dict | None:
        return self._read_json(self.session_path)

    def save_session(self, session: dict) -> None:
        self._write_json(self.session_path, session)

    # --- directory cache and key pins ---------------------------------------------------
    def load_directory_cache(self) -> dict:
        return self._read_json(self.directory_cache_path, default={"recipients": {}, "moderators": {}})

    def save_directory_cache(self, cache: dict) -> None:
        self._write_json(self.directory_cache_path, cache)

    def load_pins(self) -> dict:
        """username -> fingerprint we decided to trust."""
        return self._read_json(self.pins_path, default={})

    def save_pins(self, pins: dict) -> None:
        self._write_json(self.pins_path, pins)

    # --- tokens --------------------------------------------------------------------------
    # pending_<round>.json holds t, r and the blinded value while a request is
    # in flight. r is sensitive: together with the blinded value it would link
    # the issued token to the spent one, so the file is deleted on success.
    def load_pending(self, round_number: int) -> dict | None:
        return self._read_json(self.pending_path(round_number))

    def save_pending(self, round_number: int, pending: dict) -> None:
        make_private_dir(self.tokens_dir)
        self._write_json(self.pending_path(round_number), pending)

    def delete_pending(self, round_number: int) -> None:
        self.pending_path(round_number).unlink(missing_ok=True)

    def load_token(self, round_number: int) -> dict | None:
        return self._read_json(self.token_path(round_number))

    def save_token(self, round_number: int, token: dict) -> None:
        make_private_dir(self.tokens_dir)
        self._write_json(self.token_path(round_number), token)

    def delete_token(self, round_number: int) -> None:
        self.token_path(round_number).unlink(missing_ok=True)

    def list_token_rounds(self) -> tuple[list[int], list[int]]:
        """(rounds with a token, rounds with a pending request)."""
        tokens = []
        pending = []
        if not self.tokens_dir.exists():
            return tokens, pending
        # Files look like "3.json" (a token) or "pending_3.json" (a request).
        for path in self.tokens_dir.glob("*.json"):
            name = path.stem  # the file name without ".json"
            if name.startswith("pending_"):
                number_part = name[len("pending_"):]
                if number_part.isdigit():
                    pending.append(int(number_part))
            elif name.isdigit():
                tokens.append(int(name))
        tokens.sort()
        pending.sort()
        return tokens, pending

    # --- outbox: a built-but-unconfirmed anonymous send ---------------------------------
    # Saved before sending so that, after a crash or lost response, the SAME
    # envelope can be resubmitted: the server treats an identical resend as a
    # harmless retry, but a different envelope with the same token as a replay.
    def load_outbox(self) -> dict | None:
        return self._read_json(self.outbox_path)

    def save_outbox(self, body: dict) -> None:
        self._write_json(self.outbox_path, body)

    def delete_outbox(self) -> None:
        self.outbox_path.unlink(missing_ok=True)

    # --- audit log pin and checkpoint -----------------------------------------------
    def load_audit_pin(self) -> str | None:
        if not self.audit_pubkey_pin_path.exists():
            return None
        return self.audit_pubkey_pin_path.read_text(encoding="utf-8").strip()

    def save_audit_pin(self, public_key_b64: str) -> None:
        self.ensure_dir()
        write_private_file(self.audit_pubkey_pin_path, public_key_b64.encode("ascii"), overwrite=True)

    def load_audit_checkpoint(self) -> dict | None:
        return self._read_json(self.audit_checkpoint_path)

    def save_audit_checkpoint(self, checkpoint: dict) -> None:
        self._write_json(self.audit_checkpoint_path, checkpoint)

    # --- private key ----------------------------------------------------------------
    def has_private_key(self) -> bool:
        return self.private_key_path.exists()

    def save_private_key(self, private_key, passphrase: str) -> None:
        """PKCS#8 PEM encrypted with the passphrase (library's best scheme).

        Refuses to overwrite an existing key: losing it means losing the inbox.
        """
        self.ensure_dir()
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
        write_private_file(self.private_key_path, pem)

    def load_private_key(self, passphrase: str):
        if not self.has_private_key():
            raise ClientError("no private key in this config directory; register first")
        try:
            return serialization.load_pem_private_key(
                self.private_key_path.read_bytes(), password=passphrase.encode("utf-8")
            )
        except (ValueError, TypeError):
            # Do not echo anything about the passphrase back.
            raise ClientError("could not unlock the private key (wrong passphrase?)") from None

    def delete_private_key(self) -> None:
        self.private_key_path.unlink(missing_ok=True)
