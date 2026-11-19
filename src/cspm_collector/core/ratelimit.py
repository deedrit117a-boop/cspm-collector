"""Optional per-service token bucket."""
from __future__ import annotations

import threading
import time


class TokenBucket:
    """Allows ``rate`` acquisitions per second with bursts up to ``burst``."""

    def __init__(self, rate: float, burst: int | None = None, clock=time.monotonic, sleep=time.sleep):
        self.rate = rate
        self.capacity = float(burst or max(1, int(rate)))
        self._tokens = self.capacity
        self._clock, self._sleep = clock, sleep
        self._last = clock()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = self._clock()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                wait = (1 - self._tokens) / self.rate
            self._sleep(wait)
