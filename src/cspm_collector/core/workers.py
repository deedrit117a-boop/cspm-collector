"""Run ``(account, region, service)`` tasks with total / per-account / per-service limits.

A single scheduler thread decides what may start, so worker threads never block
on a semaphore and a busy account cannot starve the others.
"""
from __future__ import annotations

import time
from collections import Counter, deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .config import ConcurrencySettings


@dataclass(frozen=True)
class Task:
    account_id: str
    region: str  # "global" for global services
    service: str


@dataclass
class TaskResult:
    task: Task
    value: Any = None
    error: BaseException | None = None
    duration_s: float = 0.0


def _timed(fn: Callable[[Task], Any], task: Task) -> TaskResult:
    start = time.perf_counter()
    try:
        value = fn(task)
        return TaskResult(task, value=value, duration_s=time.perf_counter() - start)
    except BaseException as exc:  # noqa: BLE001 - one failing task must not stop the run
        return TaskResult(task, error=exc, duration_s=time.perf_counter() - start)


def run_tasks(
    tasks: Iterable[Task],
    fn: Callable[[Task], Any],
    limits: ConcurrencySettings | None = None,
    on_result: Callable[[TaskResult], None] | None = None,
    on_start: Callable[[Task], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> list[TaskResult]:
    """Execute ``fn`` for every task. ``on_start`` and ``on_result`` run on the calling thread. When ``cancelled()``
    turns true nothing new is started; the tasks already running finish normally."""
    limits = limits or ConcurrencySettings()
    pending = deque(tasks)
    running: dict[Future, Task] = {}
    per_account: Counter[str] = Counter()
    per_service: Counter[str] = Counter()
    results: list[TaskResult] = []

    def eligible(t: Task) -> bool:
        return per_account[t.account_id] < limits.per_account and per_service[t.service] < limits.per_service

    with ThreadPoolExecutor(max_workers=limits.total, thread_name_prefix="cspm") as pool:
        while pending or running:
            if pending and cancelled is not None and cancelled():
                pending.clear()
            while pending and len(running) < limits.total:
                idx = next((i for i, t in enumerate(pending) if eligible(t)), None)
                if idx is None:
                    break
                pending.rotate(-idx)
                task = pending.popleft()
                pending.rotate(idx)
                per_account[task.account_id] += 1
                per_service[task.service] += 1
                running[pool.submit(_timed, fn, task)] = task
                if on_start:
                    on_start(task)
            done, _ = wait(running, return_when=FIRST_COMPLETED)
            for fut in done:
                task = running.pop(fut)
                per_account[task.account_id] -= 1
                per_service[task.service] -= 1
                result = fut.result()
                results.append(result)
                if on_result:
                    on_result(result)
    return results
