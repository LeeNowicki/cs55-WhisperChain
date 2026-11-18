"""Small file helpers shared by the server and the client."""

import os
from pathlib import Path


def write_private_file(path: Path, data: bytes, overwrite: bool = False) -> None:
    """Write a file that only the current user can read.

    The file is created with mode 0o600 in the same call that creates it,
    so there is no moment where it exists with looser permissions.

    overwrite=False: O_EXCL makes this fail if the file already exists, so we
    never silently replace a secret or a private key.
    overwrite=True: write a private temp file, then atomically rename it over
    the old one, so a crash never leaves a half-written file.

    On Windows (os.name == "nt") POSIX modes are mostly ignored; we rely on
    the user-profile / data directory already being private to the user.
    """
    path = Path(path)
    if overwrite:
        # Write next to the real file first, e.g. "session.json.tmp".
        target = path.with_name(path.name + ".tmp")
        if target.exists():
            target.unlink()  # leftover from an earlier crash
    else:
        target = path

    # O_WRONLY: open for writing.  O_CREAT: create the file.
    # O_EXCL: fail if the file already exists.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        # Windows only: write bytes exactly as given (no newline translation).
        flags = flags | os.O_BINARY
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    if os.name != "nt":
        # The umask can only remove bits, but set the mode explicitly so the
        # intent is obvious.
        os.chmod(target, 0o600)
    if overwrite:
        os.replace(target, path)


def make_private_dir(path: Path) -> None:
    """Create a directory (and parents) readable only by the current user."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path, 0o700)
