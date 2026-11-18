"""Reading secrets (passwords, key passphrases) from the user.

Secrets are NEVER accepted as command-line arguments, because arguments
show up in shell history and in process listings.
"""

import getpass
import os

# Which environment variable holds each secret in demo mode.
_DEMO_ENV_VARS = {
    "password": "WC_DEMO_PASSWORD",
    "passphrase": "WC_DEMO_PASSPHRASE",
}


def demo_mode_enabled() -> bool:
    # Must be exactly "1": demo mode can only be switched on deliberately.
    return os.environ.get("WC_DEMO_MODE") == "1"


def prompt_secret(name: str, prompt_text: str | None = None) -> str:
    """Return a secret, prompting with a hidden input.

    name is "password" or "passphrase". In demo mode (WC_DEMO_MODE=1 only)
    the value is read from WC_DEMO_PASSWORD / WC_DEMO_PASSPHRASE so the
    scripted demo can run unattended.
    """
    if name not in _DEMO_ENV_VARS:
        raise ValueError(f"unknown secret name: {name}")
    if demo_mode_enabled():
        value = os.environ.get(_DEMO_ENV_VARS[name])
        if not value:
            raise RuntimeError(f"demo mode is on but {_DEMO_ENV_VARS[name]} is not set")
        return value
    if prompt_text is None:
        prompt_text = name.capitalize() + ": "   # e.g. "Password: "
    return getpass.getpass(prompt_text)


def prompt_new_secret(name: str, prompt_text: str | None = None) -> str:
    """Prompt twice for a NEW secret and require both entries to match."""
    first = prompt_secret(name, prompt_text)
    if demo_mode_enabled():
        return first  # nothing to confirm when the value comes from env
    second = prompt_secret(name, f"Confirm {name}: ")
    if first != second:
        raise ValueError(f"the two {name} entries do not match")
    return first
