"""Hardening of the control page that the company's configuration-inspection checklists ask for.

* Response headers (web-server checklist: security headers, no caching of sensitive pages, no server banner).
* Lockout after repeated wrong tokens (security-system checklist 1.5: "login failure limit 10 or fewer"; here 5 in 15 minutes,
  the same policy the team records for its other security tools).

The page has no login session, so the session-timeout item does not apply; access control (loopback + host allowlist + token),
audit log and its retention are handled in ``app.py`` / ``retention.py``.
"""
from __future__ import annotations

import threading
import time
from typing import Callable

MAX_FAILURES = 5
WINDOW_SECONDS = 15 * 60
LOCK_SECONDS = 15 * 60
MAX_TRACKED = 1000  # clients remembered at once (a flood of addresses must not grow memory without bound)

# The page is one file with its own script and style and loads nothing from other hosts.
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
API_CACHE = "no-store"


class LoginThrottle:
    """Counts wrong tokens per client address; ``locked`` says how many seconds a client still has to wait."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, max_failures: int = MAX_FAILURES,
                 window: int = WINDOW_SECONDS, lock: int = LOCK_SECONDS) -> None:
        self._clock, self._max, self._window, self._lock_for = clock, max_failures, window, lock
        self._fails: dict[str, list[float]] = {}
        self._until: dict[str, float] = {}
        self._mutex = threading.Lock()

    def locked(self, client: str) -> int:
        with self._mutex:
            left = self._until.get(client, 0) - self._clock()
            if left <= 0:
                self._until.pop(client, None)
                return 0
            return int(left) + 1

    def failed(self, client: str) -> bool:
        """Record a wrong token; True when this one locked the client."""
        with self._mutex:
            now = self._clock()
            hits = [t for t in self._fails.get(client, []) if now - t < self._window] + [now]
            if len(self._fails) >= MAX_TRACKED and client not in self._fails:
                self._fails.pop(next(iter(self._fails)))
            self._fails[client] = hits
            if len(hits) >= self._max:
                self._until[client] = now + self._lock_for
                self._fails.pop(client, None)
                return True
            return False

    def succeeded(self, client: str) -> None:
        with self._mutex:
            self._fails.pop(client, None)
