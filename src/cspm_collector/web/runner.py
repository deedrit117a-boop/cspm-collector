"""One collection at a time, in order. Manual clicks and schedules both go through here.

Why a single worker: the concurrency limits ("total tasks", "per account", ...) only mean something per run. Two runs
at once would double the load on the AWS accounts and could trip their API rate limits.
"""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable

import structlog

from cspm_collector.collectors.base import CollectOptions
from cspm_collector.core.config import Settings
from cspm_collector.core.scan import RetryPlan, ScanFilter, plan_retry, run_scan
from cspm_collector.spec.schema import CollectSpec
from cspm_collector.storage.records import new_scan_id
from cspm_collector.storage.store import Store

log = structlog.get_logger("cspm.runner")
AKAMAI = "akamai"


@dataclass
class RunInfo:
    scan_id: str
    services: list[str]
    trigger: dict
    flags: frozenset[str] = frozenset()
    accounts: tuple[str, ...] | None = None  # None: every configured account
    queued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    cancel: threading.Event = field(default_factory=threading.Event)  # set: stop starting new tasks
    retry: RetryPlan | None = None  # an automatic second try: only what the run ``retry_of`` could not do
    retry_of: str | None = None


@dataclass
class Submission:
    scan_id: str | None  # None: nothing was accepted (the first run when the services had to be split into several)
    accepted: list[str]
    skipped: dict[str, str]  # service -> why it was not queued
    scan_ids: list[str] = field(default_factory=list)


def known_services(spec: CollectSpec, settings: Settings) -> set[str]:
    names = {s.service for s in spec.services if s.enabled}
    if settings.akamai:
        names.add(AKAMAI)
    return names


class RunManager:
    def __init__(self, store: Store, load_settings: Callable[[], Settings], load_spec: Callable[[], CollectSpec],
                 run_fn: Callable = run_scan, run_kwargs: dict | None = None,
                 preflight: Callable[[list], dict[str, dict]] | None = None,
                 on_finished: Callable[[str, bool], None] | None = None):
        self.store, self._load_settings, self._load_spec = store, load_settings, load_spec
        self._on_finished = on_finished  # (scan_id, a retry of it is queued): e.g. the notifications
        self._preflight = preflight  # accounts -> {account_id: why it cannot be opened}; None: no check
        self._run_fn, self._run_kwargs = run_fn, run_kwargs or {}
        self._queue: deque[RunInfo] = deque()
        self._current: RunInfo | None = None
        self._cond = threading.Condition()
        self._stop = False
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ submitting
    def busy_services(self) -> dict[str, str]:
        """service -> "running" | "queued" (for any account)."""
        with self._cond:
            busy = {s: "queued" for r in self._queue for s in r.services}
            if self._current:
                busy.update({s: "running" for s in self._current.services})
            return busy

    def _occupied(self, r: RunInfo, all_ids: frozenset[str]) -> frozenset[str]:
        return all_ids if r.accounts is None else frozenset(r.accounts)

    def submit(self, services: Iterable[str], trigger: dict, flags: Iterable[str] = (),
               accounts: Iterable[str] | None = None) -> Submission:
        """Queue runs for the given services (and AWS accounts; ``None`` = all). The same item is never collected twice at
        once *for the same account*: sqs of account A running does not stop sqs of account B. A service whose accounts are
        all taken is skipped; otherwise it runs for the accounts that are free (services with the same free accounts share
        one run). Akamai is one unit, whatever accounts were chosen."""
        wanted = list(dict.fromkeys(services))
        settings = self._load_settings()
        known = known_services(self._load_spec(), settings)
        all_ids = frozenset(a.account_id for a in settings.accounts)
        order = list(dict.fromkeys(accounts)) if accounts is not None else [a.account_id for a in settings.accounts]
        asked = frozenset(order)
        with self._cond:
            taken: dict[str, dict[str, set[str]]] = {}  # service -> {"running"|"queued": accounts it occupies}
            runs = [("queued", r) for r in self._queue] + ([("running", self._current)] if self._current else [])
            for state, r in runs:
                for svc in r.services:
                    occ = frozenset({"*"}) if svc == AKAMAI else self._occupied(r, all_ids)
                    taken.setdefault(svc, {}).setdefault(state, set()).update(occ)
            skipped: dict[str, str] = {}
            groups: dict[frozenset[str], list[str]] = {}
            akamai = False
            for svc in wanted:
                if svc not in known:
                    skipped[svc] = "알 수 없거나 꺼져 있는 항목"
                    continue
                mine = frozenset({"*"}) if svc == AKAMAI else asked
                running_on = taken.get(svc, {}).get("running", set()) & mine
                queued_on = taken.get(svc, {}).get("queued", set()) & mine
                free = mine - running_on - queued_on
                if not free:
                    skipped[svc] = "이미 실행 중" if running_on else "이미 대기 중"
                elif svc == AKAMAI:
                    akamai = True
                else:
                    groups.setdefault(free, []).append(svc)
            if akamai:  # Akamai does not depend on the AWS accounts: it rides along with a run, or is one by itself
                first = next(iter(groups), None)
                if first is not None:
                    groups[first].append(AKAMAI)
                else:
                    groups[asked] = [AKAMAI]
            infos = []
            for free, svcs in groups.items():
                if accounts is None and free == all_ids:
                    chosen = None
                else:
                    chosen = tuple(a for a in order if a in free)
                infos.append(RunInfo(new_scan_id(), svcs, trigger, frozenset(flags), chosen))
            if not infos:
                return Submission(None, [], skipped)
            self._queue.extend(infos)
            self._cond.notify()
        return Submission(infos[0].scan_id, [x for i in infos for x in i.services], skipped, [i.scan_id for i in infos])

    def cancel(self, scan_id: str) -> str | None:
        """Take a queued run out of the queue, or tell the running one to stop starting new tasks (what is already
        running finishes). Returns "queued" / "running", or ``None`` when no such run is waiting or running."""
        with self._cond:
            for r in list(self._queue):
                if r.scan_id == scan_id:
                    self._queue.remove(r)
                    return "queued"
            if self._current and self._current.scan_id == scan_id:
                self._current.cancel.set()
                return "running"
        return None

    def accounts(self) -> list:
        return self._load_settings().accounts

    # ------------------------------------------------------------------ state
    def state(self) -> dict:
        with self._cond:
            return {
                "running": self._describe(self._current) if self._current else None,
                "queued": [self._describe(r) for r in self._queue],
            }

    @staticmethod
    def _describe(r: RunInfo) -> dict:
        return {"scan_id": r.scan_id, "services": r.services, "trigger": r.trigger,
                "accounts": list(r.accounts) if r.accounts is not None else None,
                "cancelling": r.cancel.is_set(), "queued_at": r.queued_at.isoformat(), "started_at": r.started_at.isoformat() if r.started_at else None}

    # ------------------------------------------------------------------ worker
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop = False
        self._thread = threading.Thread(target=self._loop, name="cspm-runner", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        with self._cond:
            self._stop = True
            self._cond.notify_all()
        if self._thread:
            self._thread.join(timeout)

    def wait_idle(self, timeout: float = 30.0) -> bool:
        """Block until nothing is queued or running (used by tests)."""
        end = threading.Event()
        deadline = datetime.now().timestamp() + timeout
        while datetime.now().timestamp() < deadline:
            with self._cond:
                if not self._queue and self._current is None:
                    return True
            end.wait(0.02)
        return False

    def _loop(self) -> None:
        while True:
            with self._cond:
                while not self._queue and not self._stop:
                    self._cond.wait()
                if self._stop:
                    return
                self._current = self._queue.popleft()
                self._current.started_at = datetime.now(timezone.utc)
                info = self._current
            try:
                self._execute(info)
            finally:
                with self._cond:
                    self._current = None
            self._maybe_retry(info)
            self._announce(info)

    def _announce(self, info: RunInfo) -> None:
        if self._on_finished is None:
            return
        try:
            with self._cond:
                will_retry = any(q.retry_of == info.scan_id for q in self._queue)
            self._on_finished(info.scan_id, will_retry)
        except Exception as exc:  # noqa: BLE001 - what is done with the end of a run must not hurt the worker
            log.error("run-finished hook failed", scan_id=info.scan_id, error=type(exc).__name__)

    def _maybe_retry(self, info: RunInfo) -> None:
        """After a run with failures: queue ONE automatic second run of the transient ones (timeouts, throttling, errors).
        A retry is never retried, a cancelled run is not retried, and ``auto_retry: false`` switches it off."""
        if info.retry_of is not None or info.cancel.is_set():
            return
        try:
            if not self._load_settings().auto_retry:
                return
            scan = self.store.coll("scans").find_one({"scan_id": info.scan_id}, {"status": 1})
            if not scan or scan["status"] not in ("PARTIAL", "FAILED"):
                return
            plan = plan_retry(self.store, info.scan_id, transient_only=True)
            if not plan.tasks and not plan.akamai:
                return
            services = sorted({t[2] for t in plan.tasks} | ({AKAMAI} if plan.akamai else set()))
            accounts = tuple(sorted({t[0] for t in plan.tasks})) or None
            retry = RunInfo(new_scan_id(), services, {"type": "retry", "by": "auto", "of": info.scan_id}, info.flags,
                            accounts, retry=plan, retry_of=info.scan_id)
            with self._cond:
                self._queue.appendleft(retry)  # right after this run, before whatever else is waiting
                self._cond.notify()
            log.info("automatic retry queued", of=info.scan_id, scan_id=retry.scan_id, tasks=len(plan.tasks), akamai=len(plan.akamai))
        except Exception as exc:  # noqa: BLE001 - the retry is a help: a failure here must not hurt the worker
            log.error("automatic retry failed", scan_id=info.scan_id, error=type(exc).__name__)

    def _check_accounts(self, settings: Settings, info: RunInfo) -> dict[str, dict]:
        """The pre-run check of the AWS accounts of this run: the ones that cannot be opened (with the reason)."""
        if self._preflight is None or not settings.preflight_check or not [s for s in info.services if s != AKAMAI]:
            return {}
        accounts = [a for a in settings.accounts if info.accounts is None or a.account_id in info.accounts]
        try:
            return self._preflight(accounts) if accounts else {}
        except Exception as exc:  # noqa: BLE001 - the check is a help: when it breaks, the run goes on without it
            log.error("preflight failed", scan_id=info.scan_id, error=type(exc).__name__)
            return {}

    def _execute(self, info: RunInfo) -> None:
        log.info("run started", scan_id=info.scan_id, services=info.services, trigger=info.trigger)
        try:
            settings = self._load_settings()
            flt = ScanFilter(services=set(info.services), retry=info.retry)
            if info.accounts is not None:
                # the AWS account selection does not apply to Akamai: if it is among the items, it runs for all its accounts
                flt.accounts = set(info.accounts) | ({a.name for a in settings.akamai} if AKAMAI in info.services else set())
            excluded = self._check_accounts(settings, info)
            self._run_fn(
                settings, self._load_spec(), self.store,
                flt=flt, options=CollectOptions(flags=info.flags),
                scan_id=info.scan_id, trigger=info.trigger, cancel=info.cancel, excluded=excluded, **self._run_kwargs)
        except Exception as exc:  # noqa: BLE001 - a broken run must not kill the worker
            log.error("run crashed", scan_id=info.scan_id, error=type(exc).__name__)
            error = f"{type(exc).__name__}: {exc}"[:500]
            if self.store.coll("scans").find_one({"scan_id": info.scan_id}) is None:  # failed before the scan was created
                self.store.create_scan(info.scan_id, [], "", None, {"services": info.services, "trigger": info.trigger})
            self.store.coll("scans").update_one(
                {"scan_id": info.scan_id, "status": "RUNNING"},
                {"$set": {"status": "FAILED", "finished_at": datetime.now(timezone.utc).replace(tzinfo=None),
                          "summary.error": error}})
