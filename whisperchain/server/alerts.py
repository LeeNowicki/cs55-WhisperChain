"""Alert rules. Each rule fires at most ONCE per scope (remembered in the
alert_state table) and writes an ALERT audit entry whose detail is only the
rule name. Scopes may contain ids (e.g. a recipient id) because alert_state
is never shown to anyone; the audit log itself never sees them.

Rules (thresholds come from the server config):
  FLAG_RATE             >= N flags in a round AND >= X% of that round's messages
  RECIPIENT_FLAG_SHARE  one recipient flagged >= N messages in a round AND >= X% of theirs
  REJECTION_BURST       >= N rejected token spends within the window (in-memory count)
  MODERATOR_GRANTED     the Moderator role was granted to an account
"""

import time
import uuid

from whisperchain.server.rejections import RejectionTracker


class AlertEngine:
    def __init__(self, config: dict, rejections: RejectionTracker):
        self.config = config
        self.rejections = rejections

    # --- core -----------------------------------------------------------------
    def fire(self, audit, conn, rule: str, scope: str) -> bool:
        """Record the alert once per (rule, scope). Returns True if it fired now."""
        cur = conn.execute("INSERT OR IGNORE INTO alert_state (rule, scope) VALUES (?, ?)", (rule, scope))
        if cur.rowcount == 0:
            return False  # already fired for this scope
        audit.append_audit(conn, "ALERT", "System", f"rule: {rule}")
        return True

    def after_append(self, audit, conn, action: str, detail: str) -> None:
        """Called by AuditLog after every append, inside the same transaction."""
        if action == "ALERT":
            return  # an alert must never trigger further alerts
        if action == "MESSAGE_FLAGGED":
            # detail looks like "flag: <flag id>"; cut off the "flag: " part.
            flag_id = detail[len("flag: "):]
            self._check_flag_rules(audit, conn, flag_id)
        elif action == "SPEND_REJECTED":
            self.check_rejection_burst(audit, conn)

    # --- flag rules -------------------------------------------------------------
    def _check_flag_rules(self, audit, conn, flag_id: str) -> None:
        row = conn.execute(
            "SELECT m.round, m.recipient_id FROM flags f JOIN messages m ON m.id = f.message_id WHERE f.id = ?",
            (flag_id,),
        ).fetchone()
        if row is None:
            return
        round_number = row["round"]
        recipient_id = row["recipient_id"]
        cfg = self.config

        # Rule FLAG_RATE: the whole round.
        total = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE round = ?", (round_number,)
        ).fetchone()[0]
        flagged = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE round = ? AND status = 'flagged'", (round_number,)
        ).fetchone()[0]
        enough_flags = flagged >= cfg["alert_flag_rate_min_flags"]
        enough_share = flagged >= cfg["alert_flag_rate_min_fraction"] * total
        if enough_flags and enough_share:
            self.fire(audit, conn, "FLAG_RATE", f"round:{round_number}")

        # Rule RECIPIENT_FLAG_SHARE: just this recipient's messages in the round.
        total = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE round = ? AND recipient_id = ?",
            (round_number, recipient_id),
        ).fetchone()[0]
        flagged = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE round = ? AND recipient_id = ? AND status = 'flagged'",
            (round_number, recipient_id),
        ).fetchone()[0]
        enough_flags = flagged >= cfg["alert_recipient_share_min_flags"]
        enough_share = flagged >= cfg["alert_recipient_share_min_fraction"] * total
        if enough_flags and enough_share:
            # The recipient id appears ONLY in alert_state's scope, never in the log.
            self.fire(audit, conn, "RECIPIENT_FLAG_SHARE", f"recipient:{recipient_id}:round:{round_number}")

    # --- rejection burst ------------------------------------------------------------
    def _window_scope(self) -> str:
        # One alert per fixed time bucket of the window length.
        window = self.config["alert_rejection_burst_window_seconds"]
        return f"window:{int(time.time() // window)}"

    def burst_threshold_reached(self) -> bool:
        """Cheap in-memory test, so junk requests do not each open a DB transaction."""
        return self.rejections.recent_count() >= self.config["alert_rejection_burst_count"]

    def check_rejection_burst(self, audit, conn) -> None:
        if self.burst_threshold_reached():
            self.fire(audit, conn, "REJECTION_BURST", self._window_scope())

    # --- moderator granted --------------------------------------------------------------
    def moderator_granted(self, audit, conn) -> None:
        # Every grant is its own scope, so each grant alerts exactly once.
        self.fire(audit, conn, "MODERATOR_GRANTED", f"grant:{uuid.uuid4()}")
