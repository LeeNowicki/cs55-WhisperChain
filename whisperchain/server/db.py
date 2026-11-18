"""SQLite access: connections, transactions, schema creation."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Request

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def connect(db_path: Path) -> sqlite3.Connection:
    """Open a connection configured the way the whole server expects.

    - isolation_level=None: Python does not start transactions on its own;
      we start them explicitly with write_transaction(), so it is always
      clear which statements are grouped together.
    - check_same_thread=False: FastAPI may run a request's code on a
      different thread than the one that opened the connection. Each
      request still gets its own connection, so nothing is shared.
    - foreign_keys=ON: SQLite ignores REFERENCES clauses unless asked.
    """
    conn = sqlite3.connect(
        db_path, isolation_level=None, check_same_thread=False, timeout=10
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def write_transaction(conn: sqlite3.Connection):
    """Run a block of writes as one all-or-nothing transaction.

    BEGIN IMMEDIATE takes the write lock up front, so two requests cannot
    both read "token not spent" and then both spend it. If anything inside
    the block raises, everything (including the audit entry) is rolled back.

    How it is used:
        with write_transaction(conn):
            conn.execute(...)
            conn.execute(...)

    @contextmanager turns this function into something usable with `with`.
    The code before `yield` runs when the `with` block starts; `yield` hands
    control to the code inside the block; the code after `yield` runs when
    the block ends.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn  # <- the body of the `with` block runs here
    except BaseException:
        # Something inside the block failed: undo everything, then let the
        # error carry on to the caller.
        conn.execute("ROLLBACK")
        raise
    # Only reached if the block finished without an error.
    conn.execute("COMMIT")


def create_schema(conn: sqlite3.Connection) -> None:
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema_sql)


def now_iso() -> str:
    """Current UTC time, ISO-8601, to whole seconds."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_db(request: Request):
    """FastAPI dependency: one fresh connection per request, always closed.

    FastAPI runs this up to `yield` before the route, gives `conn` to the
    route, and runs the `finally` part after the route has finished.
    """
    conn = connect(request.app.state.paths.db)
    try:
        yield conn  # <- the route function runs here
    finally:
        conn.close()  # always runs, even if the route raised an error
