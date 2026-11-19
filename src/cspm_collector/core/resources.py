"""How much work this machine can take, and how to split a big run: advice from the CPU and memory it has right now.

Collection is mostly waiting for AWS (network), so the limit is how many tasks run at once: each running task holds the
API answers it is reading, and every task and every detail call is a thread. The advice therefore recommends the
concurrency settings and, for a run that is too big, a split into runs of fewer accounts (they queue and run one after
the other; the results are the same, only the peak load is lower).

The numbers below are assumptions, measured on nothing but reasoning; they are constants on purpose so that they can be
tuned after a few real runs (compare the advice with what ``수집 건강도`` shows).
"""
from __future__ import annotations

import math
import os
import sys
import time
from dataclasses import asdict, dataclass
from statistics import median

from .config import ConcurrencySettings

PER_TASK_MB = 50  # peak memory of one running task (API answers, documents about to be saved)
BASE_MB = 400  # the server itself, the page, the database driver
MEM_SHARE = 0.6  # use at most this share of the memory that is available now
THREADS_PER_CPU = 6  # tasks mostly wait for the network: several per core are fine
DETAIL_THREADS_PER_CPU = 32  # all threads of the detail calls (total x per_resource) per core
TASKS_PER_SLOT_PER_RUN = 100  # a run should not hold more tasks than this x its concurrency
DEFAULT_TASK_SECONDS = 2.5  # one task, until real runs have been measured
LOW_MEMORY_MB = 1024


@dataclass
class HostResources:
    cpus: int
    mem_total_mb: int | None = None
    mem_available_mb: int | None = None
    cpu_busy_pct: float | None = None  # over the last fraction of a second


# ------------------------------------------------------------------------------------------------ the machine
def _windows_memory() -> tuple[int, int] | None:
    import ctypes

    class MemStatus(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong), ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong), ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

    st = MemStatus()
    st.dwLength = ctypes.sizeof(MemStatus)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
        return None
    return st.ullTotalPhys // 2**20, st.ullAvailPhys // 2**20


def _linux_memory() -> tuple[int, int] | None:
    info = {}
    with open("/proc/meminfo", encoding="ascii") as f:
        for line in f:
            key, _, rest = line.partition(":")
            info[key] = int(rest.split()[0])
    return info["MemTotal"] // 1024, info.get("MemAvailable", info.get("MemFree", 0)) // 1024


def _windows_cpu_times() -> tuple[int, int] | None:
    import ctypes
    from ctypes import wintypes

    idle, kernel, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
    if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
        return None
    t = lambda f: (f.dwHighDateTime << 32) | f.dwLowDateTime  # noqa: E731
    return t(idle), t(kernel) + t(user)  # kernel time includes the idle time


def _cpu_busy(sample_seconds: float, cpus: int) -> float | None:
    if sys.platform == "win32":
        a = _windows_cpu_times()
        if a is None:
            return None
        time.sleep(sample_seconds)
        b = _windows_cpu_times()
        if b is None or b[1] == a[1]:
            return None
        return round(100.0 * (1 - (b[0] - a[0]) / (b[1] - a[1])), 1)
    if hasattr(os, "getloadavg"):
        return round(min(100.0, 100.0 * os.getloadavg()[0] / cpus), 1)
    return None


def host_resources(sample_seconds: float = 0.25) -> HostResources:
    """What this machine has right now. Anything that cannot be read is ``None`` (the advice then ignores it)."""
    cpus = os.cpu_count() or 1
    total = avail = None
    try:
        mem = _windows_memory() if sys.platform == "win32" else _linux_memory() if sys.platform.startswith("linux") else None
        if mem:
            total, avail = mem
    except Exception:  # noqa: BLE001 - an unreadable counter is not a reason to refuse a run
        pass
    try:
        busy = _cpu_busy(sample_seconds, cpus)
    except Exception:  # noqa: BLE001
        busy = None
    return HostResources(cpus, total, avail, busy)


# ------------------------------------------------------------------------------------------------ the advice
def observed_rate_per_slot(rows: list[tuple[int, float, int]]) -> float | None:
    """Tasks per second that ONE concurrency slot got through in earlier runs, from ``(tasks, seconds, total)`` rows of
    the runs that were big enough to say something. ``None`` without such runs."""
    rates = [t / s / max(c, 1) for t, s, c in rows if t >= 50 and s > 5]
    return median(rates) if rates else None


def recommend(tasks: int, accounts: int, current: ConcurrencySettings, host: HostResources,
              rate_per_slot: float | None = None) -> dict:
    """Concurrency settings and a split for a run of ``tasks`` tasks over ``accounts`` accounts on this machine."""
    reasons: list[str] = []
    by_cpu = host.cpus * THREADS_PER_CPU
    reasons.append(f"CPU {host.cpus}코어 → 동시 작업 최대 {by_cpu}개")
    limit = by_cpu
    if host.mem_available_mb is not None:
        by_mem = max(2, int((host.mem_available_mb * MEM_SHARE - BASE_MB) // PER_TASK_MB))
        reasons.append(f"가용 메모리 {host.mem_available_mb / 1024:.1f}GB 중 {int(MEM_SHARE * 100)}%까지 쓰면 동시 작업 최대 {by_mem}개")
        limit = min(limit, by_mem)
    factor = 1.0
    if host.cpu_busy_pct is not None and host.cpu_busy_pct >= 85:
        factor = 0.5
    elif host.cpu_busy_pct is not None and host.cpu_busy_pct >= 60:
        factor = 0.75
    if factor < 1.0:
        reasons.append(f"CPU가 이미 {host.cpu_busy_pct:.0f}% 사용 중이라 {int(factor * 100)}%만 사용")
    # only ever advise LOWER than the settings: this machine could take more, but AWS rate limits are the other limit
    total = max(2, int(min(current.total, limit) * factor))  # a busy CPU takes a share of what would be advised otherwise
    per_account = max(1, min(current.per_account, total // 2 or 1))
    per_service = max(1, min(current.per_service, total))
    per_resource = max(1, min(current.per_resource, (host.cpus * DETAIL_THREADS_PER_CPU) // total))
    rec = ConcurrencySettings(total=total, per_account=per_account, per_service=per_service, per_resource=per_resource)

    per_run = total * TASKS_PER_SLOT_PER_RUN
    batches, per_batch = 1, accounts
    if tasks > per_run and accounts > 1:
        per_batch = max(1, int(accounts * per_run / tasks))
        batches = math.ceil(accounts / per_batch)
    rate = (rate_per_slot or 1 / DEFAULT_TASK_SECONDS) * total
    seconds = tasks / rate if rate else None
    low_mem = host.mem_available_mb is not None and host.mem_available_mb < LOW_MEMORY_MB
    level = "warn" if (low_mem or factor < 1.0 or total < current.total) and tasks > per_run // 2 else "split" if batches > 1 else "ok"
    return {"host": asdict(host), "recommended": rec.model_dump(), "current": current.model_dump(),
            "changed": rec.model_dump() != current.model_dump(), "batches": batches, "accounts_per_batch": per_batch,
            "tasks_per_run": per_run, "estimated_seconds": round(seconds) if seconds is not None else None,
            "estimate_from_history": rate_per_slot is not None, "level": level, "reasons": reasons,
            "low_memory": low_mem}
