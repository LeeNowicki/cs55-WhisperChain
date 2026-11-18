"""Server configuration: data-directory paths and tunable settings."""

from dataclasses import dataclass
from pathlib import Path

from whisperchain.common import constants as C


@dataclass(frozen=True)
class ServerPaths:
    """Every file the server keeps, derived from one data directory."""

    data_dir: Path

    @property
    def db(self) -> Path:
        return self.data_dir / "whisperchain.db"

    @property
    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    @property
    def jwt_secret(self) -> Path:
        return self.secrets_dir / "jwt_secret"

    @property
    def audit_key(self) -> Path:
        return self.secrets_dir / "audit_ed25519.pem"

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"

    def round_key(self, round_number: int) -> Path:
        return self.keys_dir / f"round_{round_number}.pem"

    @property
    def tls_dir(self) -> Path:
        return self.data_dir / "tls"

    @property
    def tls_cert(self) -> Path:
        return self.tls_dir / "cert.pem"

    @property
    def tls_key(self) -> Path:
        return self.tls_dir / "key.pem"


# Defaults. Alert thresholds are demo-scale on purpose (small numbers so the
# demo can trigger them). Tests pass overrides, e.g. to disable rate limits.
DEFAULT_CONFIG = {
    "rate_limit_enabled": True,
    "rate_limit_login": C.RATE_LIMIT_LOGIN,
    "rate_limit_register": C.RATE_LIMIT_REGISTER,
    "rate_limit_send": C.RATE_LIMIT_SEND,
    "rate_window_seconds": C.RATE_WINDOW_SECONDS,
    "jwt_lifetime_minutes": C.JWT_LIFETIME_MINUTES,
    "invite_expiry_days": C.INVITE_EXPIRY_DAYS,
    # SPEND_REJECTED is audited at most once per reason per this many seconds.
    "spend_reject_audit_interval_seconds": C.SPEND_REJECT_AUDIT_INTERVAL_SECONDS,
    # Alert rule thresholds
    "alert_flag_rate_min_flags": 3,
    "alert_flag_rate_min_fraction": 0.30,
    "alert_recipient_share_min_flags": 3,
    "alert_recipient_share_min_fraction": 0.50,
    "alert_rejection_burst_count": 10,
    "alert_rejection_burst_window_seconds": 60,
}


def build_config(overrides: dict | None = None) -> dict:
    """Defaults merged with overrides. Unknown keys are refused so a typo in
    a test or in the demo cannot silently do nothing."""
    config = dict(DEFAULT_CONFIG)  # a copy, so the defaults are never changed
    if overrides is None:
        overrides = {}
    for key, value in overrides.items():
        if key not in DEFAULT_CONFIG:
            raise KeyError(f"unknown config key: {key}")
        config[key] = value
    return config
