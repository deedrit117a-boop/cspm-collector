"""Thread-safe call statistics for the end-of-run summary."""
from __future__ import annotations

import threading
from collections import defaultdict


class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.calls = 0
        self.errors = 0
        self._duration_ms: dict[tuple[str, str], float] = defaultdict(float)
        self._count: dict[tuple[str, str], int] = defaultdict(int)

    def record(self, service: str, api: str, duration_ms: float, error: bool = False) -> None:
        with self._lock:
            self.calls += 1
            self.errors += error
            self._duration_ms[(service, api)] += duration_ms
            self._count[(service, api)] += 1

    def slowest(self, n: int = 10) -> list[dict]:
        with self._lock:
            rows = [
                {"service": s, "api": a, "calls": self._count[(s, a)], "total_ms": round(ms, 1)}
                for (s, a), ms in self._duration_ms.items()
            ]
        return sorted(rows, key=lambda r: r["total_ms"], reverse=True)[:n]

    def summary(self, n: int = 10) -> str:
        lines = [f"total API calls: {self.calls} (errors: {self.errors})", f"slowest {n} service/API:"]
        lines += [f"  {r['service']}.{r['api']}: {r['total_ms']} ms over {r['calls']} calls" for r in self.slowest(n)]
        return "\n".join(lines)
