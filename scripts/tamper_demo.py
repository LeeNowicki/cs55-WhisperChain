"""Show that tampering with the audit log is detected.

    python scripts/tamper_demo.py

1. Start a real server, do a few Admin actions, and verify the log (this
   also saves a checkpoint in the Admin's config directory).
2. Act as an attacker with direct access to the database file:
   a. try to UPDATE an audit row -> blocked by the append-only trigger;
   b. DROP the trigger, then edit a row anyway.
3. Run `audit verify` again: it reports the exact entry that was changed.
"""

import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from demo_support import DemoServer, DemoUser, banner

TARGET_SEQ = 2


def run(base: Path) -> None:
    server = DemoServer(base)
    try:
        banner("1. Normal operation, then a clean verification")
        server.setup_and_start()
        admin = DemoUser(base, "admin", server)
        admin.run(["configure", "--server", server.url, "--ca-cert", str(server.cert)])
        admin.run(["login", "--username", "admin"])
        admin.run(["admin", "invite", "--role", "Sender"])
        admin.run(["admin", "start-round"])
        admin.run(["audit", "verify"])
        admin.run(["audit", "show"])

        banner(f"2. Attacker edits audit entry #{TARGET_SEQ} directly in SQLite")
        conn = sqlite3.connect(server.db)
        try:
            print("$ UPDATE audit_log SET detail = 'roles: Moderator' WHERE seq = 2;")
            try:
                conn.execute("UPDATE audit_log SET detail = 'roles: Moderator' WHERE seq = ?", (TARGET_SEQ,))
                print("    (unexpected: update succeeded)")
            except sqlite3.DatabaseError as exc:
                print(f"    blocked by trigger: {exc}")

            print("$ DROP TRIGGER audit_log_no_update;   -- an attacker with file access can do this")
            conn.execute("DROP TRIGGER audit_log_no_update")
            print("$ UPDATE audit_log SET detail = 'roles: Moderator' WHERE seq = 2;")
            conn.execute("UPDATE audit_log SET detail = 'roles: Moderator' WHERE seq = ?", (TARGET_SEQ,))
            conn.commit()
            print("    row changed: the log now claims a Moderator invite was created.")
        finally:
            conn.close()

        banner("3. Verification catches it")
        admin.run(["audit", "show", "--tail", "50"])
        output = admin.run(["audit", "verify"], expect_failure=True)
        if f"seq {TARGET_SEQ}" not in output:
            raise RuntimeError("verification did not point at the edited entry")
        print(f"\nThe edited entry (seq {TARGET_SEQ}) no longer matches its hash, and the attacker")
        print("cannot recompute a valid hash + signature without the server's Ed25519 key.")
        banner("Tamper demo complete")
    finally:
        server.stop()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    base = Path(tempfile.mkdtemp(prefix="whisperchain-tamper-"))
    try:
        run(base)
    except RuntimeError as exc:
        print(f"\nTAMPER DEMO FAILED: {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(base, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
