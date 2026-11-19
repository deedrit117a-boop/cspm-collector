"""Run one scan: fan out collectors, persist results, sweep, summarize."""
from __future__ import annotations

import threading
import time
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from dataclasses import dataclass, field, replace
from typing import Callable

import structlog

from cspm_collector.collectors.base import CollectContext, CollectOptions, CollectResult, get_collector
from cspm_collector.akamai.client import EdgeGridClient
from cspm_collector.akamai.collector import SERVICE as AKAMAI
from cspm_collector.akamai.collector import AkamaiCollector
from cspm_collector.core.edges import extract_edges
from cspm_collector.core.shape import ShapeTracker
from cspm_collector.core.config import AccountSettings, AkamaiAccountSettings, Settings
from cspm_collector.core.errors import Status
from cspm_collector.core.session import AccountSession, region_supported
from cspm_collector.core.stats import Stats
from cspm_collector.core.workers import Task, TaskResult, run_tasks
from cspm_collector.spec.schema import CollectSpec, ServiceSpec
from cspm_collector.storage.records import SaveStats, StatusRecord, new_scan_id, now_utc
from cspm_collector.storage.store import Store
from cspm_collector.storage.sweep import derive_scan_status, sweepable_scopes

log = structlog.get_logger("cspm.scan")
ACCOUNT_SETUP_WORKERS = 8  # accounts opened at the same time at the start of a run

SessionFactory = Callable[[AccountSettings], AccountSession]
AkamaiClientFactory = Callable[[AkamaiAccountSettings], object]


@dataclass
class ScanFilter:
    services: set[str] | None = None
    tier: int | None = None
    regions: set[str] | None = None
    accounts: set[str] | None = None
    retry: "RetryPlan | None" = None  # only redo what a previous scan left unfinished

    def wants(self, svc: ServiceSpec) -> bool:
        if not svc.enabled or (self.tier and svc.tier != self.tier):
            return False
        return not self.services or svc.service in self.services

    def wants_akamai(self, acct: AkamaiAccountSettings) -> bool:
        """Akamai counts as a tier 1 service named "akamai"; ``accounts`` may name an Akamai account."""
        if self.tier and self.tier != 1:
            return False
        if self.services and AKAMAI not in self.services:
            return False
        if self.retry is not None and acct.name not in self.retry.akamai:
            return False
        return not self.accounts or acct.name in self.accounts


FAILURES = (Status.ACCESS_DENIED, Status.THROTTLED_GIVEUP, Status.TIMEOUT, Status.ERROR)


@dataclass(frozen=True)
class RetryPlan:
    """What a previous scan left unfinished: re-collect only that."""

    source_scan: str
    tasks: frozenset[tuple[str, str, str]] = frozenset()  # (account_id, region, service)
    accounts: frozenset[str] = frozenset()  # account setup failed: every task of the account
    akamai: frozenset[str] = frozenset()  # Akamai account names (an Akamai account is one unit)

    def wants_account(self, account_id: str) -> bool:
        return account_id in self.accounts or any(t[0] == account_id for t in self.tasks)

    def wants(self, task: Task) -> bool:
        return task.account_id in self.accounts or (task.account_id, task.region, task.service) in self.tasks


TRANSIENT = (Status.ERROR, Status.TIMEOUT, Status.THROTTLED_GIVEUP)  # worth a second try; ACCESS_DENIED is not


def plan_retry(store: Store, scan_id: str, transient_only: bool = False) -> RetryPlan:
    """Build a :class:`RetryPlan` from the failed ``collection_status`` rows of ``scan_id``. ``transient_only``: only
    timeouts, throttling and errors of single tasks (and of Akamai accounts); no denied access and no account that could
    not be opened, which a second try right away would not change."""
    if store.coll("scans").find_one({"scan_id": scan_id}) is None:
        raise ValueError(f"unknown scan '{scan_id}'")
    tasks: set[tuple[str, str, str]] = set()
    accounts: set[str] = set()
    akamai: set[str] = set()
    failed = [s.value for s in (TRANSIENT if transient_only else FAILURES)]
    for r in store.coll("collection_status").find({"scan_id": scan_id, "status": {"$in": failed}}):
        acct, region, service = r["account_id"], r["region"], r["service"]
        if acct.startswith("akamai:"):
            akamai.add(acct.split(":", 1)[1])
        elif region == "*":
            if not transient_only:
                accounts.add(acct)
        else:
            tasks.add((acct, region, service))
    return RetryPlan(scan_id, frozenset(tasks), frozenset(accounts), frozenset(akamai))


@dataclass
class ScanSummary:
    scan_id: str
    status: str
    tasks: int = 0
    resources: SaveStats = field(default_factory=SaveStats)
    statuses: Counter = field(default_factory=Counter)
    swept: int = 0
    akamai_resources: SaveStats = field(default_factory=SaveStats)
    stats: Stats = field(default_factory=Stats)


def run_scan(
    settings: Settings,
    spec: CollectSpec,
    store: Store,
    *,
    flt: ScanFilter | None = None,
    options: CollectOptions | None = None,
    session_factory: SessionFactory = AccountSession,
    akamai_client_factory: AkamaiClientFactory = EdgeGridClient.from_settings,
    scan_id: str | None = None,
    trigger: dict | None = None,
    cancel: threading.Event | None = None,
    excluded: dict[str, dict] | None = None,
) -> ScanSummary:
    """``trigger`` says who started the scan (``{"type": "manual|schedule|cli", "by": ...}``); it is stored with it."""
    flt = flt or ScanFilter()
    # the concurrency inside a task comes from the settings, like the other limits
    options = replace(options or CollectOptions(), per_resource_workers=settings.concurrency.per_resource)
    scan_id = scan_id or new_scan_id()
    services = [s for s in spec.services if flt.wants(s)]
    # an Akamai-only run (no AWS service wanted) never opens the AWS accounts: no credentials, SSO login or identity checks
    accounts = [a for a in settings.accounts if services and (not flt.accounts or a.account_id in flt.accounts)
                and (flt.retry is None or flt.retry.wants_account(a.account_id))]
    summary = ScanSummary(scan_id=scan_id, status="RUNNING")
    akamai_accounts = [a for a in settings.akamai if flt.wants_akamai(a)]
    store.create_scan(scan_id, [a.account_id for a in accounts] + [f"akamai:{a.name}" for a in akamai_accounts],
                      spec.spec_version, spec.prowler_version,
                      {"services": sorted(s.service for s in services), "tier": flt.tier,
                       "flags": sorted(options.flags), "retry_of": flt.retry.source_scan if flt.retry else None,
                       "trigger": trigger or {"type": "cli"}, "concurrency": settings.concurrency.model_dump()})

    all_status: list[StatusRecord] = []
    sessions: dict[str, AccountSession] = {}
    # accounts the pre-run check found unusable: never opened, listed with the reason like any account that failed to open
    excluded = excluded or {}
    for acct in accounts:
        why = excluded.get(acct.account_id)
        if why:
            row = StatusRecord(acct.account_id, "*", "*", "*", Status.ERROR, error_code=why.get("code") or "PREFLIGHT_FAILED",
                               error=f"{why.get('message', '')} {why.get('hint', '')}".strip(), affects_sweep=False)
            store.record_status(scan_id, [row])
            all_status.append(row)
    if excluded:
        store.coll("scans").update_one({"scan_id": scan_id}, {"$set": {"options.preflight_excluded": sorted(
            a.account_id for a in accounts if a.account_id in excluded)}})
    accounts_to_open = [a for a in accounts if a.account_id not in excluded]
    tasks: list[Task] = []
    def open_account(acct: AccountSettings) -> tuple[AccountSession, list[str]]:
        sess = session_factory(acct)
        if settings.verify_account_identity and hasattr(sess, "verify_identity"):
            sess.verify_identity()
        return sess, [r for r in sess.target_regions() if not flt.regions or r in flt.regions]

    # dozens of accounts each need credentials and an identity check (network calls): do them side by side
    with ThreadPoolExecutor(max_workers=max(1, min(ACCOUNT_SETUP_WORKERS, len(accounts_to_open)))) as pool:
        opened = {a.account_id: pool.submit(open_account, a) for a in accounts_to_open}
    for acct in accounts_to_open:
        try:
            sess, regions = opened[acct.account_id].result()
            sessions[acct.account_id] = sess
        except Exception as exc:  # noqa: BLE001 - one bad account must not stop the others
            log.error("account setup failed", account=acct.account_id, error=type(exc).__name__)
            row = StatusRecord(acct.account_id, "*", "*", "*", Status.ERROR,
                               error_code=type(exc).__name__, error=str(exc), affects_sweep=False)
            store.record_status(scan_id, [row])
            all_status.append(row)
            continue
        for svc in services:
            for region in (["global"] if svc.scope == "global" else regions):
                if (svc.scope == "regional" and settings.skip_unsupported_regions
                        and not region_supported(svc.client, region)):
                    row = StatusRecord(acct.account_id, region, svc.service, "*", Status.NOT_SUPPORTED,
                                       error="service is not available in this region (botocore endpoint data)",
                                       affects_sweep=False)
                    store.record_status(scan_id, [row])
                    all_status.append(row)
                    continue
                task = Task(acct.account_id, region, svc.service)
                if flt.retry is None or flt.retry.wants(task):
                    tasks.append(task)
    summary.tasks = len(tasks)
    by_name = {s.service: s for s in services}
    total_steps = len(tasks) + len(akamai_accounts)
    per_service: dict[str, dict] = {}  # service -> tasks / resources / seconds (longest task), for the run history
    per_account: dict[str, dict] = {}  # account -> tasks / resources / wall seconds / per-service numbers
    spans: dict[str, list[float]] = {}  # account -> [first task start, last task end] (perf_counter)
    running: Counter = Counter()
    done = 0

    shapes = ShapeTracker()
    acct_total = Counter(t.account_id for t in tasks)
    acct_done: Counter = Counter()

    def progress() -> None:
        store.update_progress(scan_id, done, total_steps, [s for s, n in running.items() if n > 0],
                              {a: {"done": acct_done[a], "total": n} for a, n in acct_total.items()})

    progress()

    def work(task: Task) -> CollectResult:
        svc = by_name[task.service]
        ctx = CollectContext(sessions[task.account_id], task.region, svc, summary.stats, options)
        if settings.incremental_details and flt.retry is None:
            ctx.previous = lambda rtype: store.previous_details(task.account_id, task.region, task.service, rtype)
            ctx.reuse_since = now_utc() - timedelta(days=max(settings.full_refresh_days, 0))
        return get_collector(svc.collector)().collect(ctx)

    def started(task: Task) -> None:
        running[task.service] += 1
        spans.setdefault(task.account_id, [time.perf_counter(), 0.0])
        progress()

    def persist(tr: TaskResult) -> None:
        nonlocal done
        t = tr.task
        done += 1
        acct_done[t.account_id] += 1
        running[t.service] -= 1
        stat = per_service.setdefault(t.service, {"tasks": 0, "resources": 0, "seconds": 0.0})
        stat["tasks"] += 1
        stat["seconds"] = round(max(stat["seconds"], tr.duration_s), 2)
        acct = per_account.setdefault(t.account_id, {"tasks": 0, "resources": 0, "seconds": 0.0, "services": {}})
        astat = acct["services"].setdefault(t.service, {"tasks": 0, "resources": 0, "seconds": 0.0, "failed": 0})
        acct["tasks"] += 1
        astat["tasks"] += 1
        astat["seconds"] = round(max(astat["seconds"], tr.duration_s), 2)
        spans.setdefault(t.account_id, [time.perf_counter() - tr.duration_s, 0.0])[1] = time.perf_counter()
        astat["failed"] += 1 if tr.error is not None else sum(1 for r in tr.value.statuses if r.status in FAILURES)
        if tr.error is None:
            stat["resources"] += len(tr.value.resources)
            acct["resources"] += len(tr.value.resources)
            astat["resources"] += len(tr.value.resources)
            if tr.value.reused:
                astat["reused"] = astat.get("reused", 0) + tr.value.reused  # details taken from the stored copy
        progress()
        if tr.error is not None:  # the collector itself crashed
            rows = [StatusRecord(t.account_id, t.region, t.service, "*", Status.ERROR,
                                 error_code=type(tr.error).__name__, error=str(tr.error), affects_sweep=False)]
            store.record_status(scan_id, rows)
            all_status.extend(rows)
            log.error("collector crashed", task=t, error=type(tr.error).__name__)
            return
        res: CollectResult = tr.value
        summary.resources.add(store.save_resources(scan_id, res.resources))
        _save_edges(store, scan_id, res.resources)
        shapes.add(res.resources)
        store.record_status(scan_id, res.statuses)
        for name, value in res.settings:
            store.save_account_setting(scan_id, t.account_id, t.region, name, value)
        all_status.extend(res.statuses)
        log.info("task done", account=t.account_id, region=t.region, service=t.service,
                 resources=len(res.resources), seconds=round(tr.duration_s, 2))

    def stopped() -> bool:
        return cancel is not None and cancel.is_set()

    run_tasks(tasks, work, settings.concurrency, on_result=persist, on_start=started, cancelled=stopped)

    for acct in akamai_accounts:
        if stopped():
            break
        running[AKAMAI] += 1
        progress()
        began = time.perf_counter()
        before = summary.akamai_resources.inserted + summary.akamai_resources.updated + summary.akamai_resources.unchanged
        _run_akamai(acct, akamai_client_factory, store, scan_id, summary, all_status)
        after = summary.akamai_resources.inserted + summary.akamai_resources.updated + summary.akamai_resources.unchanged
        stat = per_service.setdefault(AKAMAI, {"tasks": 0, "resources": 0, "seconds": 0.0})
        stat["tasks"] += 1
        stat["resources"] += after - before
        stat["seconds"] = round(max(stat["seconds"], time.perf_counter() - began), 2)
        name = f"akamai:{acct.name}"
        rows = [r for r in all_status if r.account_id == name]
        took = round(time.perf_counter() - began, 2)
        per_account[name] = {"tasks": 1, "resources": after - before, "seconds": took, "statuses": dict(Counter(r.status.value for r in rows)),
                             "status": derive_scan_status(rows), "services": {AKAMAI: {"tasks": 1, "resources": after - before, "seconds": took}}}
        running[AKAMAI] -= 1
        done += 1
        progress()

    for acct in accounts:  # one entry per requested account, also when it failed before any task ran
        entry = per_account.setdefault(acct.account_id, {"tasks": 0, "resources": 0, "seconds": 0.0, "services": {}})
        rows = [r for r in all_status if r.account_id == acct.account_id]
        first, last = spans.get(acct.account_id, [0.0, 0.0])
        entry["seconds"] = round(max(last - first, 0.0), 2)
        entry["statuses"] = dict(Counter(r.status.value for r in rows))
        entry["status"] = derive_scan_status(rows)
        failed = next((r for r in rows if r.service == "*" and r.status == Status.ERROR), None)
        if failed is not None:
            entry["error"] = f"{failed.error_code}: {failed.error}"[:400]
    summary.statuses = Counter(r.status.value for r in all_status)
    if stopped():
        # a stopped run read only part of the world: nothing may be soft-deleted because it was not seen
        summary.status = "CANCELLED"
    else:
        scopes = sweepable_scopes(all_status)
        summary.swept = store.sweep(scan_id, [s for s in scopes if s.service != AKAMAI])
        summary.swept += store.sweep(scan_id, [s for s in scopes if s.service == AKAMAI], collection="akamai_raw")
        store.sweep(scan_id, scopes, collection="edges")  # an edge goes away with the complete scope of its source
        # a retry of a scan that had nothing to redo is a success, while a normal scan that collected nothing is not
        summary.status = "COMPLETED" if flt.retry is not None and not all_status else derive_scan_status(all_status)
    store.save_scan_accounts(scan_id, per_account)
    shape_changes = []
    if summary.status == "COMPLETED" and flt.retry is None and not services_partial(flt):
        try:  # an extra: a problem here must never cost the scan
            shape_changes = shapes.finish(store, now_utc())
        except Exception as exc:  # noqa: BLE001
            log.error("shape check failed", scan_id=scan_id, error=type(exc).__name__)
    store.finish_scan(scan_id, summary.status, {
        "tasks": summary.tasks, "resources": vars(summary.resources),
        "akamai_resources": vars(summary.akamai_resources), "swept": summary.swept,
        "statuses": dict(summary.statuses), "api_calls": summary.stats.calls,
        "slowest": summary.stats.slowest(10), "services": per_service, "shape_changes": shape_changes})
    return summary


def services_partial(flt: ScanFilter) -> bool:
    """A run limited to some regions sees fewer resources of a type: its field names say nothing about the others."""
    return bool(flt.regions)


def _save_edges(store: Store, scan_id: str, resources) -> None:
    """The relationships are an extra: a problem there must never cost the collection itself."""
    try:
        store.save_edges(scan_id, extract_edges(resources))
    except Exception as exc:  # noqa: BLE001
        log.error("saving edges failed", scan_id=scan_id, error=type(exc).__name__)


def _run_akamai(acct: AkamaiAccountSettings, factory: AkamaiClientFactory, store: Store, scan_id: str,
                summary: ScanSummary, all_status: list[StatusRecord]) -> None:
    account_id = f"akamai:{acct.name}"
    try:
        result = AkamaiCollector(factory(acct), acct, summary.stats).collect()
    except Exception as exc:  # noqa: BLE001 - bad credentials / unreadable .edgerc must not stop the AWS results
        log.error("akamai setup failed", account=account_id, error=type(exc).__name__)
        rows = [StatusRecord(account_id, "*", AKAMAI, "*", Status.ERROR, error_code=type(exc).__name__,
                             error=str(exc), affects_sweep=False)]
        store.record_status(scan_id, rows)
        all_status.extend(rows)
        return
    summary.akamai_resources.add(store.save_resources(scan_id, result.resources, collection="akamai_raw"))
    _save_edges(store, scan_id, result.resources)
    store.record_status(scan_id, result.statuses)
    all_status.extend(result.statuses)
    log.info("akamai done", account=account_id, documents=len(result.resources))
