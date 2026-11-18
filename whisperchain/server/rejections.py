"""Counting rejected token spends without letting junk flood the audit log.

Anyone can POST garbage to the anonymous send endpoint. Writing an audit
entry for every rejection would let an attacker bloat the permanent log, so
each reject REASON is audited at most once per window. Every rejection is
still counted in memory; Stage 8's REJECTION_BURST alert reads that count.
"""

import threading
import time
from collections import deque

REASONS = ("bad_signature", "replay", "frozen", "closed_round", "bad_recipient")


class RejectionTracker:
    def __init__(self, audit_interval_seconds: float, burst_window_seconds: float):
        self.audit_interval = audit_interval_seconds
        self.burst_window = burst_window_seconds
        self._last_audited: dict[str, float] = {}
        self._recent: deque = deque()  # timestamps of all recent rejections
        self._lock = threading.Lock()

    def record(self, reason: str, now: float | None = None) -> bool:
        """Count one rejection. Returns True if it should be audited now."""
        if reason not in REASONS:
            raise ValueError(f"unknown reject reason: {reason}")
        if now is None:
            now = time.monotonic()  # tests may pass their own `now` instead
        with self._lock:
            self._recent.append(now)
            last = self._last_audited.get(reason)
            if last is None or now - last >= self.audit_interval:
                self._last_audited[reason] = now
                return True
            return False

    def recent_count(self, now: float | None = None) -> int:
        """Rejections within the burst window (for the alert rule)."""
        if now is None:
            now = time.monotonic()
        with self._lock:
            while self._recent and self._recent[0] <= now - self.burst_window:
                self._recent.popleft()
            return len(self._recent)
