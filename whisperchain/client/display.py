"""Making server-supplied text safe to print in a terminal."""

import re

# C0 control characters (except tab and newline), DEL, and C1 controls.
# Removing them stops a malicious message from sending terminal escape
# sequences (e.g. to clear the screen or fake other output).
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize(text: str) -> str:
    return _CONTROL_CHARS.sub("", text)
