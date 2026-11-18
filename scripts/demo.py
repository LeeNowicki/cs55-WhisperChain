"""End-to-end demo of WhisperChain+ with a real TLS server and real CLI users.

    python scripts/demo.py            # runs in a temporary directory, then cleans up
    python scripts/demo.py --keep     # keep the temporary directory to inspect it

Story: an Admin sets up a round and invites three Senders (alice, carol,
dave), a Recipient (bob) and a Moderator (mia). Each Sender gets a blind
token and anonymously sends bob one message. bob reads and flags all three,
which triggers alerts. mia reviews, freezes one flag and dismisses another,
then verifies the audit log, which is saved to docs/sample_audit_log.txt.
"""

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

from demo_support import REPO, UUID_RE, DemoServer, DemoUser, banner

SAMPLE_LOG = REPO / "docs" / "sample_audit_log.txt"

MESSAGES = {
    "alice": "Hi Bob, the quarterly numbers in your report look wrong.",
    "carol": "You are useless and everyone knows it.",
    "dave": "Lunch on Friday? Unicode works too: café ✓",
}


def run_demo(base: Path) -> None:
    server = DemoServer(base)
    try:
        banner("1. Server setup: init, init-admin, run (TLS)")
        server.setup_and_start()

        banner("2. Admin logs in, opens round 1 and invites users")
        admin = DemoUser(base, "admin", server)
        admin.run(["configure", "--server", server.url, "--ca-cert", str(server.cert)])
        admin.run(["login", "--username", "admin"])
        admin.run(["admin", "start-round"])

        users = {}
        for name in ["alice", "carol", "dave", "bob", "mia"]:
            users[name] = DemoUser(base, name, server)
        for name in ["alice", "carol", "dave"]:
            users[name].setup(admin, ["Sender"])
        users["bob"].setup(admin, ["Recipient"])
        users["mia"].setup(admin, ["Moderator"])  # fires the MODERATOR_GRANTED alert
        admin.run(["admin", "users"])

        banner("3. Senders sync keys (TOFU pins), get blind tokens, send anonymously")
        for name, text in MESSAGES.items():
            sender = users[name]
            sender.run(["keys", "sync"])
            sender.run(["token", "request"])
            sender.run(["send", "--to", "bob", "--message", text, "--now"])

        banner("4. One token per round: a second send by alice is refused")
        users["alice"].run(["send", "--to", "bob", "--message", "second message", "--now"], expect_failure=True)
        users["alice"].run(["token", "request"], expect_failure=True)  # the server refuses a second token
        users["alice"].run(["token", "status"])

        banner("5. bob reads his inbox (decrypted locally, never stored in plaintext)")
        bob = users["bob"]
        bob.run(["keys", "sync"])
        bob.run(["keys", "fingerprint"])
        inbox_output = bob.run(["inbox"])
        message_ids = UUID_RE.findall(inbox_output)  # every id-shaped string in the output
        for message_id in message_ids:
            bob.run(["inbox", "--show", message_id])

        banner("6. bob flags all three messages (moderator gets a key copy for each)")
        for message_id in message_ids:
            bob.run(["flag", message_id, "--reason", "please review", "--yes"])

        banner("7. mia reviews the queue, freezes one flag, dismisses another")
        mia = users["mia"]
        queue_output = mia.run(["mod", "queue"])
        flag_ids = UUID_RE.findall(queue_output)
        mia.run(["mod", "review", flag_ids[0]])
        mia.run(["mod", "freeze", flag_ids[0]])
        mia.run(["mod", "review", flag_ids[1]])
        mia.run(["mod", "dismiss", flag_ids[1]])
        mia.run(["mod", "queue"])

        banner("8. Access control: roles cannot exceed their permissions")
        users["carol"].run(["inbox"], expect_failure=True)          # Sender cannot read inboxes
        bob.run(["admin", "users"], expect_failure=True)            # Recipient is not Admin
        admin.run(["mod", "queue"], expect_failure=True)            # Admin cannot see flags/content

        banner("9. Alerts and audit log verification")
        admin.run(["alerts"])
        mia.run(["audit", "verify"])
        log_text = mia.run(["audit", "show"], quiet=True)
        print("    (full log written to docs/sample_audit_log.txt)")

        SAMPLE_LOG.parent.mkdir(exist_ok=True)
        SAMPLE_LOG.write_text(
            "# Sample WhisperChain+ audit log, produced by `python scripts/demo.py`.\n"
            "# Columns: seq, timestamp (UTC), action, acting role, detail.\n"
            "# Note: no usernames, user ids, tokens, message ids, or IPs appear anywhere.\n\n"
            + log_text + "\n",
            encoding="utf-8",
        )
        banner("Demo complete")
    finally:
        server.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true", help="keep the temporary demo directory")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    base = Path(tempfile.mkdtemp(prefix="whisperchain-demo-"))
    try:
        run_demo(base)
    except RuntimeError as exc:
        print(f"\nDEMO FAILED: {exc}", file=sys.stderr)
        return 1
    finally:
        if args.keep:
            print(f"Demo files kept in {base}")
        else:
            shutil.rmtree(base, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
