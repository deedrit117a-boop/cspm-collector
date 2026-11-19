"""Fires the saved schedules. Everything that is due at a tick goes into ONE run (fewer, bigger scans)."""
from __future__ import annotations

import socket
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable
from zoneinfo import ZoneInfo

import structlog

from .groups import GroupError, Groups, Target
from .runner import RunManager
from .schedule import Schedule, next_run
from .state import WebState

log = structlog.get_logger("cspm.scheduler")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Scheduler:
    def __init__(self, state: WebState, runner: RunManager, tz: ZoneInfo, *, owner: str | None = None,
                 tick_seconds: float = 20.0, lease_seconds: int = 60, clock: Callable[[], datetime] = _now,
                 region_batch=None, retention=None):
        self.state, self.runner, self.tz = state, runner, tz
        self.retention = retention  # callable(now) -> removed counts (None when switched off): the daily clean-up of old data, or None
        self.region_batch = region_batch  # RegionDetectRunner: the periodic look for regions an account uses but has not listed
        self.groups = Groups(state.store)
        self.owner = owner or f"{socket.gethostname()}-{uuid.uuid4().hex[:6]}"
        self.tick_seconds, self.lease_seconds, self.clock = tick_seconds, lease_seconds, clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def tick(self, now: datetime | None = None) -> dict:
        """One pass. Returns ``{"leader", "triggered", "skipped", "scan_id"}`` (handy for tests and logs)."""
        now = now or self.clock()
        if not self.state.acquire_lease(self.owner, self.lease_seconds, now):
            return {"leader": False, "triggered": [], "skipped": {}, "scan_id": None}
        self.state.store.interrupt_stale_scans(now=now)  # a scan whose process died must not stay "running" forever
        self._region_check(now)
        self._retention_check(now)
        due = self.state.due(now)
        if not due:
            return {"leader": True, "triggered": [], "skipped": {}, "scan_id": None}
        # a missed period (server was down) runs once, not once per missed period; items with the same account
        # selection share one run
        accounts_cfg = self.runner.accounts()
        by_target: dict[tuple | None, list[dict]] = {}
        failed: dict[str, str] = {}
        for d in due:
            try:
                ids = self.groups.resolve_accounts(Target(**(d.get("target") or {})), accounts_cfg)
            except GroupError as exc:  # e.g. the group was deleted: report it, never silently widen to all accounts
                failed[d["_id"]] = str(exc)
                continue
            by_target.setdefault(tuple(ids) if ids is not None else None, []).append(d)
        triggered: list[str] = []
        skipped: dict[str, str] = dict(failed)
        scan_ids: list[str] = []
        for ids, docs in by_target.items():
            sub = self.runner.submit([d["_id"] for d in docs], trigger={"type": "schedule", "by": "scheduler"},
                                     accounts=ids)
            triggered += sub.accepted
            skipped.update(sub.skipped)
            if sub.scan_id:
                scan_ids.append(sub.scan_id)
            for d in docs:
                reason = sub.skipped.get(d["_id"])
                self._mark(d, now, sub.scan_id if reason is None else None, reason)
        for d in due:
            if d["_id"] in failed:
                self._mark(d, now, None, failed[d["_id"]])
        if skipped:
            self.state.audit("scheduler", "skipped", {"skipped": skipped}, now)
        log.info("schedules fired", services=triggered, skipped=skipped, scan_ids=scan_ids)
        return {"leader": True, "triggered": triggered, "skipped": skipped,
                "scan_id": scan_ids[0] if scan_ids else None, "scan_ids": scan_ids}

    def _region_check(self, now: datetime) -> None:
        """Start the used-region detection of all accounts when the last one is older than ``region_check_days``."""
        if self.region_batch is None:
            return
        try:
            days = self.runner._load_settings().region_check_days
            if days <= 0:
                return
            coll = self.state.store.coll("runtime")
            last = (coll.find_one({"_id": "region_detect_meta"}) or {}).get("last_started")
            naive = now.astimezone(timezone.utc).replace(tzinfo=None)
            if last is not None and (naive - last).total_seconds() < days * 86400:
                return
            _, started = self.region_batch.start(None, "scheduler")
            if started:
                coll.update_one({"_id": "region_detect_meta"}, {"$set": {"last_started": naive}}, upsert=True)
        except Exception as exc:  # noqa: BLE001 - a bad check must not stop the schedules
            log.error("region check failed", error=type(exc).__name__)

    def _retention_check(self, now: datetime) -> None:
        """Once a day (when switched on on the settings page) delete what is older than the chosen periods."""
        if self.retention is None:
            return
        try:
            coll = self.state.store.coll("runtime")
            naive = now.astimezone(timezone.utc).replace(tzinfo=None)
            last = (coll.find_one({"_id": "retention_meta"}) or {}).get("last_run")
            if last is not None and (naive - last).total_seconds() < 86400:
                return
            removed = self.retention(now)
            if removed is None:  # switched off
                return
            coll.update_one({"_id": "retention_meta"}, {"$set": {"last_run": naive, "removed": removed}}, upsert=True)
            if removed:
                self.state.audit("scheduler", "retention", {"removed": removed}, now)
        except Exception as exc:  # noqa: BLE001 - a clean-up problem must not stop the schedules
            log.error("retention failed", error=type(exc).__name__)

    def _mark(self, d: dict, now: datetime, scan_id: str | None, reason: str | None) -> None:
        nxt = next_run(Schedule(**d["schedule"]), now.astimezone(self.tz))
        self.state.mark_triggered(d["_id"], now, nxt, scan_id, reason)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="cspm-scheduler", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001 - a bad tick must not end the scheduler
                log.error("scheduler tick failed", error=type(exc).__name__)
            self._stop.wait(self.tick_seconds)
