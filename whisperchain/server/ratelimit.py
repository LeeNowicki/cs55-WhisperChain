"""In-memory, per-IP, sliding-window rate limiting.

Nothing is persisted: a restart clears the counters. That is acceptable
because the limits only slow down online guessing and flooding.
"""

import threading
import time
from collections import deque

from fastapi import HTTPException, Request


class SlidingWindowLimiter:
    """Allow at most `limit` events per `window` seconds for each key."""

    def __init__(self, limit: int, window: float):
        self.limit = limit
        self.window = window
        self._events: dict[str, deque] = {}
        # Requests are handled on several threads; the lock keeps the
        # check-then-record step atomic.
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        if now is None:
            now = time.monotonic()  # tests may pass their own `now` instead
        with self._lock:
            # First request from this key (IP address): start an empty list.
            if key not in self._events:
                self._events[key] = deque()
            events = self._events[key]
            # Forget events that slid out of the window.
            while events and events[0] <= now - self.window:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True


def build_limiters(config: dict) -> dict:
    window = config["rate_window_seconds"]
    return {
        "login": SlidingWindowLimiter(config["rate_limit_login"], window),
        "register": SlidingWindowLimiter(config["rate_limit_register"], window),
        "send": SlidingWindowLimiter(config["rate_limit_send"], window),
    }


def rate_limited(name: str):
    """FastAPI dependency factory: reject with 429 when over the limit."""

    def check(request: Request) -> None:
        if not request.app.state.config["rate_limit_enabled"]:
            return
        if request.client is not None:
            ip = request.client.host
        else:
            ip = "unknown"
        if not request.app.state.limiters[name].allow(ip):
            raise HTTPException(status_code=429, detail="too many requests; slow down")

    return check
