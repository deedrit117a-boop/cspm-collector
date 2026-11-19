"""The control page's HTTP API (FastAPI) and the single-file page itself.

Safety model
* The server binds to localhost by default (see ``collect web``); a bearer token can be required for everything else.
* Every ``/api`` request must carry the ``Host`` of this server (blocks DNS-rebinding from a web page) and every
  state-changing request a custom header that browsers will not send cross-site without a CORS preflight (no CORS here).
* The page never handles AWS or MongoDB credentials; the server uses its own environment.
"""
from __future__ import annotations

import hmac
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from cspm_collector.core.config import AccountSettings, ConcurrencySettings, Settings
from cspm_collector.core.regions import Detection, detect_used_regions, open_session
from cspm_collector.core.resources import HostResources, host_resources, observed_rate_per_slot, recommend
from cspm_collector.spec.loader import load_spec
from cspm_collector.spec.schema import CollectSpec
from cspm_collector.storage.store import Store

from .accounts import MAX_CSV_BYTES, AccountBody, AccountError, WebAccounts, available_profiles, parse_csv, to_csv
from . import retention as retention_mod
from .changes import KINDS, change_detail, recent_changes, resource_detail
from .checks import CheckRunner, classify
from .notify import Notifier, NotifySettings
from .organizations import ImportOrgBody, OrgError, bodies as org_bodies, list_organization_accounts
from .retention import RetentionSettings
from .actions import akamai_summary, edges_status, needs_action
from .health import collection_health, freshness
from .region_batch import RegionDetectRunner, drift
from .groups import GroupCreate, GroupError, Groups, GroupUpdate, Target, group_csv, plan_group_csv
from .runner import AKAMAI, RunManager
from .security import API_CACHE, HEADERS as SECURITY_HEADERS, LoginThrottle
from .schedule import Schedule, describe
from .state import ConcurrencyUpdate, WebState, naive_utc

STATIC = Path(__file__).parent / "static"
UI_HEADER = "x-cspm-ui"


@dataclass
class WebDeps:
    settings: Settings
    store: Store
    state: WebState
    runner: RunManager
    spec_path: str
    tz: ZoneInfo
    token: str | None = None
    user_header: str | None = None  # e.g. "X-Forwarded-User" behind an SSO proxy
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "[::1]")
    load_settings: Callable[[], Settings] | None = None  # settings as of now (file + page edits); default: the file's
    checker: CheckRunner | None = None  # connection checks of the accounts (background batch + latest results)
    detector: Callable[[AccountSettings, tuple[str, ...]], Detection] | None = None  # used-region detection (tests inject a fake)
    region_batch: RegionDetectRunner | None = None  # the same detection for many accounts in the background
    host_probe: Callable[[], HostResources] | None = None  # CPU / memory of this machine (tests inject a fake)
    notifier: Notifier | None = None  # chat notifications (settings page)
    org_lister: Callable[[], dict] | None = None  # accounts of the AWS Organization (tests inject a fake)


def detect_regions(account: AccountSettings, always: tuple[str, ...]) -> Detection:
    sess = open_session(account)
    sess.verify_identity()  # never report the regions of another account than the one on the screen
    return detect_used_regions(sess, always=always)


class ScheduleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auto: bool
    schedule: Schedule
    target: Target = Target()  # which accounts; empty = all


class BulkScheduleBody(ScheduleBody):
    services: list[str] = Field(min_length=1)


class ImportBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    csv: str
    apply: bool = False  # False: only check and report what would happen
    use_profiles: bool = False  # accounts whose name is an AWS profile of this machine use that profile


class CheckBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_ids: list[str] | None = None  # None: every account


class ApplyRegionsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_ids: list[str]  # accounts whose detected regions are written into their ``regions``


class RetentionRunBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: bool = False  # the user saw how much would be deleted


class RunBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    services: list[str] = []
    item_groups: list[str] = []  # item groups to add to ``services``
    target: Target = Target()  # which accounts; empty = all
    flags: list[str] = []
    confirm: bool = False  # the user saw the warning about a very large run and wants it anyway
    batch_size: int | None = Field(None, ge=1, le=500)  # split the accounts into runs of this many (they queue one after the other)


class EstimateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    services: list[str] = []
    item_groups: list[str] = []
    target: Target = Target()


# Bump when the page needs an API that older servers do not have: the page then tells the user to restart the server
# (a page file is always read fresh from disk, while a running server keeps its old code until it is restarted).
BIG_RUN_TASKS = 500  # a manual run above this many tasks needs a confirmation (scheduled runs are set up on purpose)
UNKNOWN_REGIONS = 17  # tasks per regional item for an account whose regions are discovered when the run starts
API_LEVEL = 16

PROBLEMS_PER_ACCOUNT = 80  # lines of an account's own problem log in a run's detail


def _account_status(statuses: dict[str, int]) -> str:
    """Status of one account from its collection-status counts (for runs that stored no per-account summary)."""
    bad = sum(n for k, n in statuses.items() if k not in ("SUCCESS", "SKIPPED", "NOT_ENABLED", "NOT_SUPPORTED"))
    ok = statuses.get("SUCCESS", 0)
    return "FAILED" if bad and not ok else "PARTIAL" if bad else "COMPLETED"


def iso(value: Any) -> Any:
    """JSON-ready copy: MongoDB's naive UTC datetimes become ISO strings with a ``Z``; ``_id`` is dropped."""
    if isinstance(value, datetime):
        dt = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"
    if isinstance(value, dict):
        return {k: iso(v) for k, v in value.items() if k != "_id"}
    if isinstance(value, list):
        return [iso(v) for v in value]
    return value


def create_app(deps: WebDeps) -> FastAPI:
    app = FastAPI(title="CSPM collector control page", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(deps.allowed_hosts))
    throttle = LoginThrottle()

    @app.middleware("http")
    async def harden(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", API_CACHE)
        return response

    spec_cache: dict[str, Any] = {"mtime": None, "spec": None}

    def spec() -> CollectSpec:
        mtime = Path(deps.spec_path).stat().st_mtime
        if spec_cache["mtime"] != mtime:
            spec_cache.update(mtime=mtime, spec=load_spec(deps.spec_path))
        return spec_cache["spec"]

    def now() -> datetime:
        return datetime.now(timezone.utc)

    def who(request: Request) -> str:
        if deps.user_header and request.headers.get(deps.user_header):
            return request.headers[deps.user_header][:80]
        return "local"

    def guard(request: Request) -> None:
        if deps.token:
            client = request.client.host if request.client else "?"
            wait = throttle.locked(client)
            if wait:
                raise HTTPException(429, f"인증 실패가 반복되어 잠겼습니다. {wait // 60 + 1}분 뒤에 다시 시도하세요", headers={"Retry-After": str(wait)})
            given = request.headers.get("authorization", "")
            given = given[7:] if given.lower().startswith("bearer ") else request.headers.get("x-cspm-token", "")
            if not hmac.compare_digest(given.encode(), deps.token.encode()):
                if throttle.failed(client):
                    deps.state.audit(f"client:{client}", "auth_locked", {"client": client}, now())
                raise HTTPException(401, "인증이 필요합니다")
            throttle.succeeded(client)
        if request.method not in ("GET", "HEAD") and UI_HEADER not in request.headers:
            raise HTTPException(403, "허용되지 않는 요청입니다")

    api = Depends(guard)
    groups = Groups(deps.store)
    web_accounts = WebAccounts(deps.store)

    def cfg() -> Settings:
        return deps.load_settings() if deps.load_settings else deps.settings

    # ------------------------------------------------------------------ helpers
    def accounts_view() -> list[dict]:
        added = {a.account_id for a in web_accounts.list()}
        from_file = {a.account_id for a in deps.settings.accounts}
        return [{"account_id": a.account_id, "name": a.name, "env": a.env, "regions": a.regions, "role_arn": a.role_arn,
                 "profile": a.profile,
                 "external_id_env": a.external_id_env,
                 "source": "file" if a.account_id in from_file else "web" if a.account_id in added else "file"}
                for a in cfg().accounts]

    def resolve_target(target: Target) -> list[str] | None:
        try:
            return groups.resolve_accounts(target, cfg().accounts)
        except GroupError as exc:
            raise HTTPException(422, str(exc)) from exc

    def tasks_for(scope: str, accounts: list) -> int | None:
        """Tasks one item creates per run: global = one per account, regional = one per configured region.
        ``None`` when an account has no fixed region list (regions are discovered when the run starts)."""
        total = 0
        for a in accounts:
            if scope == "global":
                total += 1
            elif a.regions is None:
                return None
            else:
                total += len(a.regions)
        return total

    def last_runs() -> dict[str, dict]:
        found: dict[str, dict] = {}
        fields = {"scan_id": 1, "status": 1, "started_at": 1, "finished_at": 1, "summary.services": 1}
        for scan in deps.store.coll("scans").find({"summary.services": {"$exists": True}}, fields).sort("started_at", -1).limit(400):
            for service, stat in scan["summary"]["services"].items():
                found.setdefault(service, {
                    "scan_id": scan["scan_id"], "status": scan["status"], "started_at": scan["started_at"],
                    "finished_at": scan.get("finished_at"), "resources": stat["resources"], "seconds": stat["seconds"],
                    "tasks": stat["tasks"]})
        return found

    def opt_in_flags(service: str) -> list[str]:
        svc = next((s for s in spec().services if s.service == service), None)
        return sorted({a.opt_in_flag for a in svc.apis if a.opt_in_flag}) if svc else []

    def item_names() -> set[str]:
        names = {s.service for s in spec().services if s.enabled}
        return names | ({AKAMAI} if cfg().akamai else set())

    # ------------------------------------------------------------------ pages
    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "api_level": API_LEVEL}

    # ------------------------------------------------------------------ overview
    @app.get("/api/overview", dependencies=[api])
    def overview() -> dict:
        running = deps.runner.state()
        progress = None
        if running["running"]:
            doc = deps.store.coll("scans").find_one({"scan_id": running["running"]["scan_id"]}, {"progress": 1, "started_at": 1})
            progress = iso((doc or {}).get("progress"))
            running["running"]["started_at"] = iso((doc or {}).get("started_at")) or running["running"]["started_at"]
        defaults = ConcurrencySettings()
        return {
            "timezone": str(deps.tz), "now": iso(naive_utc(now())), "accounts": accounts_view(), "api_level": API_LEVEL,
            "akamai": [a.name for a in cfg().akamai], "auth": bool(deps.token),
            "region_drift": iso(drift(region_batch.results(), cfg().accounts)),
            "region_check_days": cfg().region_check_days,
            "concurrency": deps.state.concurrency(deps.settings.concurrency).model_dump(),
            "concurrency_defaults": defaults.model_dump(),
            "concurrency_limits": {k: [f.metadata[0].ge, f.metadata[1].le]
                                   for k, f in ConcurrencyUpdate.model_fields.items()},
            "run": {**running, "progress": progress},
        }

    # ------------------------------------------------------------------ items
    @app.get("/api/items", dependencies=[api])
    def items() -> dict:
        saved, busy, last = deps.state.schedules(), deps.runner.busy_services(), last_runs()
        conf = cfg()  # once: it reads the page's settings from the database
        rows = []
        for s in sorted((s for s in spec().services if s.enabled), key=lambda s: (s.tier, s.service)):
            rows.append(("aws", s.service, s.tier, s.scope, len(s.apis), tasks_for(s.scope, conf.accounts), opt_in_flags(s.service)))
        if conf.akamai:
            rows.insert(0, ("akamai", AKAMAI, 1, "global", 0, len(conf.akamai), []))
        out = []
        for kind, name, tier, scope, n_api, tasks, flags in rows:
            doc = saved.get(name)
            sched = Schedule(**doc["schedule"]) if doc else Schedule()
            out.append(iso({
                "service": name, "source": kind, "tier": tier, "scope": scope, "api_count": n_api, "tasks": tasks,
                "opt_in_flags": flags, "auto": bool(doc and doc.get("auto")), "schedule": sched.model_dump(),
                "target": (doc or {}).get("target") or {"accounts": [], "account_groups": []},
                "schedule_text": describe(sched), "next_run": (doc or {}).get("next_run"),
                "last_triggered_at": (doc or {}).get("last_triggered_at"), "last_skip": (doc or {}).get("last_skip"),
                "last_run": last.get(name), "state": busy.get(name, "idle")}))
        return {"items": out, "tz": str(deps.tz)}

    def save_schedule(service: str, body: ScheduleBody, user: str) -> dict:
        resolve_target(body.target)  # refuse a selection that names nothing or something unknown
        return deps.state.set_schedule(service, body.schedule, body.auto, user, now(), body.target.model_dump())

    @app.put("/api/items/{service}/schedule", dependencies=[api])
    def put_schedule(service: str, body: ScheduleBody, request: Request) -> dict:
        if service not in item_names():
            raise HTTPException(404, "알 수 없는 항목입니다")
        return iso(save_schedule(service, body, who(request)))

    @app.post("/api/items/schedule", dependencies=[api])
    def bulk_schedule(body: BulkScheduleBody, request: Request) -> dict:
        unknown = [s for s in body.services if s not in item_names()]
        if unknown:
            raise HTTPException(404, f"알 수 없는 항목: {', '.join(unknown)}")
        user = who(request)
        for service in body.services:
            save_schedule(service, body, user)
        return {"updated": body.services}

    # ------------------------------------------------------------------ runs
    def estimate_run(services: list[str], account_ids: list[str] | None) -> dict:
        """How many (account, region, item) tasks a run would create, for the confirmation of very large runs."""
        scope_of = {s.service: s.scope for s in spec().services}
        chosen = [a for a in cfg().accounts if account_ids is None or a.account_id in account_ids]
        tasks, approx = 0, False
        for svc in services:
            if svc == AKAMAI:
                tasks += len(cfg().akamai)
                continue
            for a in chosen:
                if scope_of.get(svc) == "global":
                    tasks += 1
                elif a.regions:
                    tasks += len(a.regions)
                else:
                    tasks, approx = tasks + UNKNOWN_REGIONS, True
        return {"tasks": tasks, "accounts": len(chosen), "services": len(services), "approx": approx}

    def advice_for(big: dict) -> dict:
        """Settings and a split for this run on this machine (``core/resources``); the speed comes from earlier big runs."""
        rows = []
        for sc in deps.store.coll("scans").find({"status": "COMPLETED", "summary.tasks": {"$gte": 50}},
                                                {"started_at": 1, "finished_at": 1, "summary.tasks": 1, "options": 1}).sort("started_at", -1).limit(20):
            opts = sc.get("options") or {}
            if (opts.get("trigger") or {}).get("type") == "retry" or not sc.get("finished_at") or not sc.get("started_at"):
                continue
            rows.append((sc["summary"]["tasks"], (sc["finished_at"] - sc["started_at"]).total_seconds(),
                         (opts.get("concurrency") or {}).get("total") or deps.settings.concurrency.total))
        host = (deps.host_probe or host_resources)()
        return recommend(big["tasks"], max(big["accounts"], 1), deps.state.concurrency(deps.settings.concurrency), host,
                         observed_rate_per_slot(rows))

    @app.post("/api/runs/estimate", dependencies=[api])
    def estimate(body: EstimateBody) -> dict:
        """How big a run would be and what this machine can take: the numbers the page shows before the user starts it."""
        try:
            services = list(dict.fromkeys([*body.services, *groups.resolve_items(body.item_groups)]))
        except GroupError as exc:
            raise HTTPException(422, str(exc)) from exc
        big = estimate_run(services, resolve_target(body.target))
        return {**big, "big": big["tasks"] > BIG_RUN_TASKS, "limit": BIG_RUN_TASKS, "advice": advice_for(big)}

    @app.post("/api/runs", status_code=202, dependencies=[api])
    def start_run(body: RunBody, request: Request) -> dict:
        known_flags = {f for s in spec().services for a in s.apis for f in [a.opt_in_flag] if f}
        bad = [f for f in body.flags if f not in known_flags]
        if bad:
            raise HTTPException(422, f"알 수 없는 옵트인 플래그: {', '.join(bad)}")
        user = who(request)
        try:
            services = list(dict.fromkeys([*body.services, *groups.resolve_items(body.item_groups)]))
        except GroupError as exc:
            raise HTTPException(422, str(exc)) from exc
        if not services:
            raise HTTPException(422, "수집할 항목을 선택하세요")
        accounts = resolve_target(body.target)
        big = estimate_run(services, accounts)
        if big["tasks"] > BIG_RUN_TASKS and not body.confirm:
            raise HTTPException(409, {"code": "CONFIRM_NEEDED", **big, "limit": BIG_RUN_TASKS, "advice": advice_for(big),
                                      "message": f"예상 작업이 {big['tasks']:,}개{'(리전을 비운 어카운트는 17개로 어림)' if big['approx'] else ''}로 많습니다."})
        trigger = {"type": "manual", "by": user}
        if body.batch_size and (accounts is None or len(accounts) > body.batch_size):
            # runs of ``batch_size`` accounts, queued one after the other; Akamai (not tied to the accounts) goes with the first
            ids = accounts if accounts is not None else [a.account_id for a in cfg().accounts]
            chunks = [ids[i:i + body.batch_size] for i in range(0, len(ids), body.batch_size)]
            group = uuid.uuid4().hex[:8]  # the runs of one request share it: the history shows "batch 2/3"
            subs = [deps.runner.submit([s for s in services if n == 0 or s != AKAMAI], {**trigger, "batch": {"n": n + 1, "of": len(chunks), "id": group}},
                                       body.flags, chunk) for n, chunk in enumerate(chunks)]
        else:
            subs = [deps.runner.submit(services, trigger, body.flags, accounts)]
        scan_ids = [i for s in subs for i in s.scan_ids]
        accepted = list(dict.fromkeys(x for s in subs for x in s.accepted))
        skipped = {k: v for s in subs for k, v in s.skipped.items() if k not in accepted}
        deps.state.audit(user, "run", {"services": services, "accounts": accounts, "accepted": accepted, "skipped": skipped,
                                       "scan_id": scan_ids[0] if scan_ids else None, "batches": len(subs)}, now())
        if not scan_ids:
            raise HTTPException(409, {"message": "새로 시작할 항목이 없습니다", "skipped": skipped})
        return {"scan_id": scan_ids[0], "scan_ids": scan_ids, "accepted": accepted, "skipped": skipped, "batches": len(subs)}

    @app.post("/api/runs/{scan_id}/cancel", dependencies=[api])
    def cancel_run(scan_id: str, request: Request) -> dict:
        """Take a queued run out of the queue, or stop a running one from starting new tasks (the tasks already running
        finish; nothing is soft-deleted because of a cancelled run)."""
        how = deps.runner.cancel(scan_id)
        if how is None:
            raise HTTPException(404, "대기 중이거나 실행 중인 수집이 아닙니다 (이미 끝났을 수 있습니다)")
        deps.state.audit(who(request), "run_cancel", {"scan_id": scan_id, "was": how}, now())
        return {"scan_id": scan_id, "cancelled": how}

    @app.get("/api/health/collection", dependencies=[api])
    def get_collection_health(limit: int = 10) -> dict:
        """How each account did over the last runs and what looks wrong (consecutive failures, slow runs, items that
        suddenly return far fewer resources). See ``web/health.py``."""
        names = {a.account_id: a.name or a.account_id for a in cfg().accounts}
        names.update({f"akamai:{a.name}": f"{a.name} (Akamai)" for a in cfg().akamai})
        return iso(collection_health(deps.store, names, limit))

    @app.get("/api/health/freshness", dependencies=[api])
    def get_freshness(days: int = 7) -> dict:
        """How old the data of each account and item is (last run without a failed call); see ``web/health.py``."""
        names = {a.account_id: a.name or a.account_id for a in cfg().accounts}
        names.update({f"akamai:{a.name}": f"{a.name} (Akamai)" for a in cfg().akamai})
        return iso(freshness(deps.store, names, days))

    @app.get("/api/health/actions", dependencies=[api])
    def get_actions() -> dict:
        """Accounts that cannot be collected as things stand and what to do about each (see ``web/actions.py``)."""
        names = {a.account_id: a.name or a.account_id for a in cfg().accounts}
        return iso(needs_action(deps.store, names))

    @app.get("/api/health/edges", dependencies=[api])
    def get_edges_status() -> dict:
        return iso(edges_status(deps.store, naive_utc(now())))

    @app.get("/api/akamai/summary", dependencies=[api])
    def get_akamai_summary() -> dict:
        return iso(akamai_summary(deps.store))

    @app.get("/api/runs", dependencies=[api])
    def runs(limit: int = 30) -> dict:
        rows = []
        light = {"summary.services": 0, "summary.accounts": 0, "summary.slowest": 0, "summary.statuses": 0}  # shown in the details only
        for scan in deps.store.coll("scans").find({}, light).sort("started_at", -1).limit(max(1, min(limit, 200))):
            summ = scan.get("summary") or {}
            res = summ.get("resources") or {}
            elapsed = (scan["finished_at"] - scan["started_at"]).total_seconds() if scan.get("finished_at") else None
            rows.append(iso({
                "scan_id": scan["scan_id"], "status": scan["status"], "started_at": scan["started_at"],
                "finished_at": scan.get("finished_at"), "seconds": elapsed,
                "services": (scan.get("options") or {}).get("services", []), "trigger": (scan.get("options") or {}).get("trigger"),
                "accounts": scan.get("accounts"),
                "resources": sum(res.get(k, 0) for k in ("inserted", "updated", "unchanged")) + sum(
                    (summ.get("akamai_resources") or {}).get(k, 0) for k in ("inserted", "updated", "unchanged")),
                "inserted": res.get("inserted", 0), "updated": res.get("updated", 0), "unchanged": res.get("unchanged", 0),
                "api_calls": summ.get("api_calls"), "tasks": summ.get("tasks"), "progress": scan.get("progress"),
                "error": summ.get("error")}))
        return {"runs": rows, "queue": deps.runner.state()}

    @app.get("/api/runs/{scan_id}", dependencies=[api])
    def run_detail(scan_id: str) -> dict:
        scan = deps.store.coll("scans").find_one({"scan_id": scan_id})
        if not scan:
            # waiting in the queue, or taken by the worker but its record is not written yet: answer in the shape of a
            # run that has not reported anything (the page asks again every few seconds)
            state = deps.runner.state()
            running = state["running"] if state["running"] and state["running"]["scan_id"] == scan_id else None
            run = running or next((q for q in state["queued"] if q["scan_id"] == scan_id), None)
            if run:
                return {"scan_id": scan_id, "status": "RUNNING" if running else "QUEUED", "live": True,
                        "started_at": None, "finished_at": None, "seconds": None, "options": None, "accounts": run.get("accounts"),
                        "progress": None, "summary": {}, "services": [], "account_stats": [], "status_counts": {},
                        "problems": [], "queued_services": run["services"]}
            raise HTTPException(404, "실행 기록이 없습니다")
        summ = scan.get("summary") or {}
        names = {a.account_id: a.name or a.account_id for a in cfg().accounts}
        names.update({f"akamai:{a.name}": f"{a.name} (Akamai)" for a in cfg().akamai})
        counts: dict[str, int] = {}
        by_acct: dict[str, dict] = {}  # account -> status counts, per-service status counts and its own problem log
        seen_regions: dict[str, dict[str, set]] = {}  # account -> service -> regions that have a recorded result
        flat_problems: list[dict] = []
        for r in deps.store.coll("collection_status").find({"scan_id": scan_id}):
            st, acct, svc = r["status"], r.get("account_id"), r.get("service")
            counts[st] = counts.get(st, 0) + 1
            entry = by_acct.setdefault(acct, {"statuses": {}, "services": {}, "problems": []})
            entry["statuses"][st] = entry["statuses"].get(st, 0) + 1
            if svc and svc != "*":
                sv = entry["services"].setdefault(svc, {})
                sv[st] = sv.get(st, 0) + 1
                seen_regions.setdefault(acct, {}).setdefault(svc, set()).add(r.get("region"))
            if st not in ("SUCCESS", "SKIPPED"):
                row = {k: r.get(k) for k in ("service", "region", "api", "status", "error_code", "error")}
                if len(entry["problems"]) < PROBLEMS_PER_ACCOUNT:  # a log per account, so that no account hides the others
                    entry["problems"].append(row)
                if len(flat_problems) < 200:
                    flat_problems.append(row | {"account_id": acct, "account": names.get(acct, acct)})
        saved = deps.store.scan_accounts(scan_id) or summ.get("accounts") or {}  # older scans kept them in the scan document
        # runs from before the per-account numbers existed: list the accounts from what was recorded
        ids = list(saved) or [a for a in (scan.get("accounts") or [])] + [a for a in by_acct if a not in (scan.get("accounts") or [])]
        live = scan["status"] == "RUNNING"
        live_progress = (scan.get("progress") or {}).get("accounts") or {}
        scope_of = {sv.service: sv.scope for sv in spec().services}
        conf_accounts = {a.account_id: a for a in cfg().accounts}
        wanted = list((scan.get("options") or {}).get("services") or [])
        running_now = set((scan.get("progress") or {}).get("running") or [])
        account_stats = []
        for acct in ids:
            v, logged = saved.get(acct) or {}, by_acct.get(acct, {"statuses": {}, "services": {}, "problems": []})
            statuses = v.get("statuses") or logged["statuses"]
            services = {s: dict(x) for s, x in (v.get("services") or {}).items()}
            for svc, sc in logged["services"].items():
                services.setdefault(svc, {"tasks": None, "resources": None, "seconds": None})["statuses"] = sc
            if live:  # items not started yet are part of the picture while the run goes on
                for svc in wanted:
                    services.setdefault(svc, {"tasks": None, "resources": None, "seconds": None})
            account = conf_accounts.get(acct)
            prog = live_progress.get(acct)
            state = None
            if live and prog:
                state = "done" if prog["total"] and prog["done"] >= prog["total"] else "running" if prog["done"] else "pending"
                if prog["total"] == 0 and acct in by_acct:
                    state = "done"  # nothing to run for it (it failed to open or has no supported region)
            for svc, x in services.items():
                done = len(seen_regions.get(acct, {}).get(svc, ()))
                total = 1 if scope_of.get(svc) == "global" or svc == "akamai" else (len(account.regions) if account and account.regions else None)
                x["done"], x["total"] = done, total
                x["state"] = (("pending" if not done else "done" if total is not None and done >= total else "running") if live
                              else "done" if done else "none")
                # a task is written down when it ends, so an item that is being collected right now has no row yet: the
                # run knows which items are in progress (not in which account), so for an account that is working show those
                if live and x["state"] == "pending" and state == "running" and svc in running_now:
                    x["state"] = "running"
                    x["maybe"] = True  # "being collected in this or another account"

            account_stats.append({
                "account_id": acct, "name": names.get(acct, acct), "status": v.get("status") or _account_status(statuses),
                "tasks": v.get("tasks"), "resources": v.get("resources"), "seconds": v.get("seconds"), "statuses": statuses,
                "error": v.get("error"), "has_numbers": bool(v), "progress": prog, "state": state,
                "problem_count": sum(n for k, n in statuses.items() if k not in ("SUCCESS", "SKIPPED")),
                "problems": logged["problems"], "services": [{"service": s, **x} for s, x in sorted(services.items())]})
        elapsed = (scan["finished_at"] - scan["started_at"]).total_seconds() if scan.get("finished_at") else None
        return iso({
            "scan_id": scan_id, "status": scan["status"], "started_at": scan["started_at"],
            "finished_at": scan.get("finished_at"), "seconds": elapsed, "options": scan.get("options"),
            "accounts": scan.get("accounts"),
            "progress": scan.get("progress"), "summary": {k: summ.get(k) for k in ("tasks", "resources", "akamai_resources",
                                                                                  "swept", "api_calls", "error")},
            "services": [{"service": s, **v} for s, v in sorted((summ.get("services") or {}).items())],
            "account_stats": sorted(account_stats, key=lambda a: str(a["name"]).lower()),
            "status_counts": counts, "problems": flat_problems, "live": live})

    # ------------------------------------------------------------------ accounts added on the page
    def account_error(exc: Exception) -> HTTPException:
        return HTTPException(422, str(exc))

    def import_warnings(good: list[AccountBody]) -> list[str]:
        """Things that are valid but probably not what the user wants (shown next to the preview; they do not block it)."""
        out: list[str] = []
        regions = [tuple(b.regions) for b in good if b.regions]
        for only in {r for r in regions if len(r) == 1}:
            n = sum(1 for r in regions if r == only)
            if n >= 2 and n >= len(good) * 0.8:
                out.append(f"{n}개 어카운트의 리전이 모두 {only[0]} 하나뿐입니다. 의도한 값이 맞는지 확인하세요 "
                           f"(양식의 예시 값을 그대로 둔 것은 아닌지). 비우면 활성 리전 전체를 수집하고, 어카운트 화면의 \"사용 리전 탐지\"로 채울 수 있습니다.")
        blank = sum(1 for b in good if not b.regions)
        if blank:
            out.append(f"{blank}개 어카운트는 리전이 비어 있어 활성 리전 전체(약 {UNKNOWN_REGIONS}개)를 수집합니다. 수집 작업이 많아집니다.")
        missing = sorted({b.external_id_env for b in good if b.external_id_env and not os.environ.get(b.external_id_env)})
        if missing:
            out.append(f"이 서버에 설정되지 않은 ExternalId 환경변수: {', '.join(missing)}. 수집할 때 해당 어카운트가 실패합니다. "
                       f"서버를 시작하기 전에 설정하거나, 프로필 방식이면 이 열을 비우세요.")
        return out

    @app.get("/api/accounts.csv", dependencies=[api])
    def export_accounts() -> PlainTextResponse:
        return PlainTextResponse("\ufeff" + to_csv(cfg().accounts), media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": 'attachment; filename="accounts.csv"'})

    @app.post("/api/accounts/import", dependencies=[api])
    def import_accounts(body: ImportBody, request: Request) -> dict:
        """Add / update accounts from CSV text. Without ``apply`` nothing is saved; with it, nothing is saved either
        unless every row is fine (a half-imported file is hard to untangle)."""
        if len(body.csv.encode()) > MAX_CSV_BYTES:
            raise HTTPException(413, "CSV가 너무 큽니다 (200KB 이하)")
        try:
            profiles_here = available_profiles()
            parsed = parse_csv(body.csv, profiles_here, body.use_profiles)
        except AccountError as exc:
            raise account_error(exc) from exc
        from_file = {a.account_id for a in deps.settings.accounts}
        added = {a.account_id for a in web_accounts.list()}
        rows, good = [], []
        for r in parsed:
            if r["error"]:
                rows.append({"line": r["line"], "account_id": r.get("account_id", ""), "action": "error", "message": r["error"]})
                continue
            b = r["body"]
            if b.profile and b.profile not in profiles_here:
                rows.append({"line": r["line"], "account_id": b.account_id, "action": "error",
                             "message": f"이 서버의 AWS 설정에 없는 프로필입니다: {b.profile}"})
                continue
            if b.account_id in from_file:  # already managed by config.yaml: not an error, just left alone
                rows.append({"line": r["line"], "account_id": b.account_id, "name": b.name, "action": "skip",
                             "message": "config.yaml에 있는 어카운트라 건너뜁니다"})
                continue
            rows.append({"line": r["line"], "account_id": b.account_id, "name": b.name,
                         "action": "update" if b.account_id in added else "add", "message": r.get("note") or ""})
            good.append(b)
        counts = {k: sum(1 for r in rows if r["action"] == k) for k in ("add", "update", "skip", "error")}
        warnings = import_warnings(good)
        applied = bool(body.apply and good and not counts["error"])
        if applied:
            user = who(request)
            web_accounts.upsert_many(good, user, now())
            deps.state.audit(user, "account_import", {"added": counts["add"], "updated": counts["update"],
                                                      "accounts": [b.account_id for b in good]}, now())
        return {"rows": rows, "counts": counts, "applied": applied, "warnings": warnings}

    # ------------------------------------------------------------------ connection check of the accounts
    def checks_view() -> dict:
        job = deps.checker.job() if deps.checker else None
        return {"job": iso(job), "results": iso(deps.checker.results()) if deps.checker else {}}

    @app.get("/api/accounts/check", dependencies=[api])
    def get_checks() -> dict:
        return checks_view()

    @app.post("/api/accounts/check", status_code=202, dependencies=[api])
    def start_checks(body: CheckBody, request: Request) -> dict:
        """Check the connection of some or all accounts in the background. Poll ``GET /api/accounts/check``."""
        if deps.checker is None:
            raise HTTPException(503, "연결 확인을 쓸 수 없습니다")
        known = {a.account_id for a in cfg().accounts}
        unknown = [i for i in (body.account_ids or []) if i not in known]
        if unknown:
            raise HTTPException(422, f"설정에 없는 어카운트: {', '.join(unknown)}")
        if body.account_ids is not None and not body.account_ids:
            raise HTTPException(422, "확인할 어카운트를 선택하세요")
        user = who(request)
        job, started = deps.checker.start(body.account_ids, user)
        if started:
            deps.state.audit(user, "account_check", {"accounts": job["total"], "all": body.account_ids is None}, now())
        return {**checks_view(), "started": started}

    def check_profile(body: AccountBody) -> None:
        if body.profile and body.profile not in available_profiles():
            raise HTTPException(422, f"이 서버의 AWS 설정(~/.aws/config)에 없는 프로필입니다: {body.profile}")

    @app.post("/api/accounts/detect-regions", dependencies=[api])
    def detect_account_regions(body: AccountBody, request: Request) -> dict:
        """Which enabled regions of this account hold something (free read-only probes, see ``core/regions``). Takes the
        account as typed in the dialog, so it works before the account is saved; ``regions`` are kept as pinned."""
        check_profile(body)
        acct = body.to_settings()
        try:
            found = (deps.detector or detect_regions)(acct, tuple(body.regions or ()))
        except Exception as exc:  # noqa: BLE001 - tell the user why, like the connection check does
            code, message, hint = classify(exc, acct)
            raise HTTPException(422, f"{message} {hint}".strip()) from exc
        deps.state.audit(who(request), "account_detect_regions", {"account_id": acct.account_id, "used": found.by_state("used")}, now())
        return {"account_id": acct.account_id, "seconds": found.seconds, "collect": found.collect,
                "used": found.by_state("used"), "unused": found.by_state("unused"), "unknown": found.by_state("unknown"),
                "regions": [vars(r) for r in found.regions]}

    # ------------------------------------------------------------------ used-region detection of many accounts
    if deps.region_batch is None:
        deps.region_batch = RegionDetectRunner(deps.store, lambda: cfg().accounts,
                                               lambda acct, always: (deps.detector or detect_regions)(acct, always))
    region_batch = deps.region_batch

    def regions_view() -> dict:
        return {"job": iso(region_batch.job()), "results": iso(region_batch.results())}

    @app.get("/api/accounts/regions/detect", dependencies=[api])
    def get_region_detection() -> dict:
        return regions_view()

    @app.post("/api/accounts/regions/detect", status_code=202, dependencies=[api])
    def start_region_detection(body: CheckBody, request: Request) -> dict:
        """Detect the used regions of some or all accounts in the background. Poll ``GET /api/accounts/regions/detect``."""
        known = {a.account_id for a in cfg().accounts}
        unknown = [i for i in (body.account_ids or []) if i not in known]
        if unknown:
            raise HTTPException(422, f"설정에 없는 어카운트: {', '.join(unknown)}")
        if body.account_ids is not None and not body.account_ids:
            raise HTTPException(422, "탐지할 어카운트를 선택하세요")
        user = who(request)
        job, started = region_batch.start(body.account_ids, user)
        if started:
            deps.state.audit(user, "region_detect", {"accounts": job["total"], "all": body.account_ids is None}, now())
        return {**regions_view(), "started": started}

    @app.post("/api/accounts/regions/apply", dependencies=[api])
    def apply_detected_regions(body: ApplyRegionsBody, request: Request) -> dict:
        """Write the detected regions (used ones + the pinned ones) into the chosen accounts. Accounts of ``config.yaml``
        and accounts without a usable result are skipped and named. An empty result is never written (empty = all regions)."""
        user = who(request)
        results, in_file = region_batch.results(), {a.account_id for a in deps.settings.accounts}
        by_id = {a.account_id: a for a in cfg().accounts}
        applied, skipped = {}, {}
        for aid in dict.fromkeys(body.account_ids):
            res, acct = results.get(aid), by_id.get(aid)
            if acct is None:
                skipped[aid] = "설정에 없는 어카운트"
            elif aid in in_file:
                skipped[aid] = "설정 파일(config.yaml)의 어카운트는 화면에서 고칠 수 없음"
            elif not res or not res.get("ok"):
                skipped[aid] = "탐지 결과가 없거나 실패함"
            elif not res.get("collect"):
                skipped[aid] = "사용 중인 리전이 발견되지 않아 바꾸지 않음"
            else:
                try:
                    web_accounts.update(aid, AccountBody(**{**acct.model_dump(), "regions": res["collect"]}), user, now())
                except (AccountError, ValueError) as exc:
                    skipped[aid] = str(exc)
                else:
                    applied[aid] = res["collect"]
        if applied:
            deps.state.audit(user, "region_apply", {"accounts": applied}, now())
        return {"applied": applied, "skipped": skipped}

    @app.get("/api/profiles", dependencies=[api])
    def profiles() -> dict:
        return {"profiles": sorted(available_profiles())}

    @app.post("/api/accounts", status_code=201, dependencies=[api])
    def add_account(body: AccountBody, request: Request) -> dict:
        user = who(request)
        check_profile(body)
        try:
            web_accounts.add(body, {a.account_id for a in cfg().accounts}, user, now())
        except AccountError as exc:
            raise account_error(exc) from exc
        deps.state.audit(user, "account_add", body.model_dump(), now())
        return next(a for a in accounts_view() if a["account_id"] == body.account_id)

    @app.put("/api/accounts/{account_id}", dependencies=[api])
    def edit_account(account_id: str, body: AccountBody, request: Request) -> dict:
        user = who(request)
        if account_id in {a.account_id for a in deps.settings.accounts}:
            raise HTTPException(409, "설정 파일(config.yaml)의 어카운트는 화면에서 고칠 수 없습니다")
        check_profile(body)
        try:
            web_accounts.update(account_id, body, user, now())
        except KeyError:
            raise HTTPException(404, "어카운트가 없습니다") from None
        except AccountError as exc:
            raise account_error(exc) from exc
        deps.state.audit(user, "account_update", body.model_dump(), now())
        return next(a for a in accounts_view() if a["account_id"] == account_id)

    @app.delete("/api/accounts/{account_id}", dependencies=[api])
    def delete_account(account_id: str, request: Request) -> dict:
        if account_id in {a.account_id for a in deps.settings.accounts}:
            raise HTTPException(409, "설정 파일(config.yaml)의 어카운트는 화면에서 지울 수 없습니다")
        if not web_accounts.delete(account_id, who(request), now()):
            raise HTTPException(404, "어카운트가 없습니다")
        in_groups = groups.remove_account(account_id)
        used = [s for s, d in deps.state.schedules().items() if account_id in (d.get("target") or {}).get("accounts", [])]
        deps.state.audit(who(request), "account_delete", {"account_id": account_id, "removed_from_groups": in_groups,
                                                           "schedules_naming_it": used}, now())
        return {"deleted": account_id, "removed_from_groups": in_groups, "schedules_naming_it": used}

    # ------------------------------------------------------------------ groups
    def valid_members(kind: str) -> set[str]:
        return item_names() if kind == "items" else {a.account_id for a in cfg().accounts}

    def group_view(doc: dict) -> dict:
        return iso({k: doc.get(k) for k in ("_id", "kind", "name", "members", "builtin", "updated_at", "updated_by")}
                   | {"id": doc["_id"], "builtin": bool(doc.get("builtin"))})

    @app.get("/api/groups", dependencies=[api])
    def list_groups() -> dict:
        views = [group_view(g) for g in groups.list()]
        return {"items": [g for g in views if g["kind"] == "items"],
                "accounts": [group_view(g) for g in groups.env_groups(cfg().accounts)]
                            + [g for g in views if g["kind"] == "accounts"]}

    @app.get("/api/groups.csv", dependencies=[api])
    def export_groups() -> PlainTextResponse:
        return PlainTextResponse("\ufeff" + group_csv(groups.list()), media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": 'attachment; filename="groups.csv"'})

    @app.post("/api/groups/import", dependencies=[api])
    def import_groups(body: ImportBody, request: Request) -> dict:
        """Create / replace / change / delete groups from CSV text (see ``plan_group_csv``). Without ``apply`` only
        report; with it nothing is saved unless every row is fine."""
        if len(body.csv.encode()) > MAX_CSV_BYTES:
            raise HTTPException(413, "CSV가 너무 큽니다 (200KB 이하)")
        current = [*groups.env_groups(cfg().accounts), *groups.list()]
        used = {}
        for d in deps.state.schedules().values():
            for gid in (d.get("target") or {}).get("account_groups", []):
                used[gid] = used.get(gid, 0) + 1
        valid = {"items": item_names(), "accounts": {a.account_id for a in cfg().accounts}}
        try:
            rows = plan_group_csv(body.csv, current, valid, used)
        except GroupError as exc:
            raise HTTPException(422, str(exc)) from exc
        counts = {k: sum(1 for r in rows if r["op"] == k) for k in ("create", "replace", "add", "remove", "delete")}
        counts["error"] = sum(1 for r in rows if r["error"])
        applied = bool(body.apply and rows and not counts["error"])
        if applied:
            user = who(request)
            for r in rows:
                existing = next((g for g in groups.list(r["kind"]) if g["name"] == r["name"]), None)
                try:
                    if r["op"] == "create":
                        groups.create(GroupCreate(kind=r["kind"], name=r["name"], members=r["members"]), valid[r["kind"]], user, now())
                    elif r["op"] == "replace":
                        groups.update(existing["_id"], GroupUpdate(members=r["members"]), valid[r["kind"]], user, now())
                    elif r["op"] in ("add", "remove"):
                        groups.update(existing["_id"], GroupUpdate(**{r["op"]: r["members"]}), valid[r["kind"]], user, now())
                    elif r["op"] == "delete":
                        groups.delete(existing["_id"])
                except GroupError as exc:  # was checked while planning; only a concurrent edit gets here
                    raise HTTPException(409, f"{r['line']}줄: {exc}") from exc
            deps.state.audit(user, "group_import", {k: v for k, v in counts.items() if v}, now())
        return {"rows": [{k: r[k] for k in ("line", "kind", "name", "action", "op", "message", "error")} | {"members": len(r["members"])}
                         for r in rows], "counts": counts, "applied": applied}

    @app.post("/api/groups", status_code=201, dependencies=[api])
    def create_group(body: GroupCreate, request: Request) -> dict:
        user = who(request)
        try:
            doc = groups.create(body, valid_members(body.kind), user, now())
        except GroupError as exc:
            raise HTTPException(422, str(exc)) from exc
        deps.state.audit(user, "group_create", {"id": doc["_id"], "kind": doc["kind"], "name": doc["name"],
                                                "members": doc["members"]}, now())
        return group_view(doc)

    @app.put("/api/groups/{group_id}", dependencies=[api])
    def update_group(group_id: str, body: GroupUpdate, request: Request) -> dict:
        existing = groups.get(group_id)
        if not existing:
            raise HTTPException(404, "그룹이 없습니다")
        user = who(request)
        try:
            doc = groups.update(group_id, body, valid_members(existing["kind"]), user, now())
        except GroupError as exc:
            raise HTTPException(422, str(exc)) from exc
        deps.state.audit(user, "group_update", {"id": group_id, "name": doc["name"], "members": doc["members"]}, now())
        return group_view(doc)

    @app.delete("/api/groups/{group_id}", dependencies=[api])
    def delete_group(group_id: str, request: Request) -> dict:
        doc = groups.delete(group_id)
        if not doc:
            raise HTTPException(404, "그룹이 없습니다")
        in_use = [s for s, d in deps.state.schedules().items() if group_id in (d.get("target") or {}).get("account_groups", [])]
        deps.state.audit(who(request), "group_delete", {"id": group_id, "name": doc["name"], "kind": doc["kind"],
                                                         "was_used_by_schedules": in_use}, now())
        return {"deleted": group_id, "schedules_using_it": in_use}

    # ------------------------------------------------------------------ accounts of the AWS Organization
    @app.post("/api/accounts/organizations/list", dependencies=[api])
    def organization_accounts() -> dict:
        """The accounts of the AWS Organization that this server's credentials can see (read-only), marked with the ones the
        collector already has."""
        try:
            found = (deps.org_lister or list_organization_accounts)()
        except OrgError as exc:
            raise HTTPException(422, str(exc)) from exc
        have = {a.account_id for a in cfg().accounts}
        manager = (found.get("organization") or {}).get("management_account_id")
        rows = [{**a, "registered": a["account_id"] in have, "management": a["account_id"] == manager} for a in found["accounts"]]
        return iso({"organization": found.get("organization"), "accounts": sorted(rows, key=lambda r: str(r["name"]).lower())})

    @app.post("/api/accounts/organizations/import", dependencies=[api])
    def organization_import(body: ImportOrgBody, request: Request) -> dict:
        """Add the chosen organization accounts (each with the same read-only role name; the collector assumes it in each).
        Accounts that are already known are left alone; nothing is written for accounts that are not active members."""
        try:
            found = (deps.org_lister or list_organization_accounts)()
        except OrgError as exc:
            raise HTTPException(422, str(exc)) from exc
        taken = {a.account_id for a in cfg().accounts}
        wanted = [i for i in dict.fromkeys(body.account_ids) if i not in taken]
        skipped = {i: "이미 등록된 어카운트" for i in body.account_ids if i in taken}
        good = []
        if wanted:
            try:
                good, why = org_bodies(found["accounts"], body.model_copy(update={"account_ids": wanted}))
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
            skipped.update(why)
        if good:
            user = who(request)
            web_accounts.upsert_many(good, user, now())
            deps.state.audit(user, "account_import_org", {"added": [g.account_id for g in good], "role_name": body.role_name,
                                                          "env": body.env}, now())
        return {"added": [g.account_id for g in good], "skipped": skipped}

    # ------------------------------------------------------------------ what changed
    @app.get("/api/changes", dependencies=[api])
    def changes(days: int = 7, kinds: str = ",".join(KINDS), service: str | None = None, account_id: str | None = None,
                q: str | None = None, limit: int = 200) -> dict:
        """New, changed and deleted resources of the last days, newest first (see ``web/changes.py``)."""
        wanted = tuple(k for k in kinds.split(",") if k in KINDS) or KINDS
        names = {a.account_id: a.name or a.account_id for a in cfg().accounts}
        events = recent_changes(deps.store, naive_utc(now()), days, wanted, service or None, account_id or None, q or None, limit)
        return iso({"events": [{**e, "account": names.get(e["account_id"], e["account_id"])} for e in events], "days": days})

    @app.get("/api/changes/detail", dependencies=[api])
    def changes_detail(id: str) -> dict:
        found = change_detail(deps.store, id)
        if found is None:
            raise HTTPException(404, "변경 기록을 찾을 수 없습니다 (보관 기간이 지나 지워졌을 수 있습니다)")
        return iso(found)

    @app.get("/api/resources/detail", dependencies=[api])
    def get_resource_detail(key: str) -> dict:
        found = resource_detail(deps.store, key)
        if found is None:
            raise HTTPException(404, "리소스를 찾을 수 없습니다 (보관 기간이 지나 지워졌을 수 있습니다)")
        return iso(found)

    @app.get("/api/health/shape", dependencies=[api])
    def shape_changes(days: int = 14) -> dict:
        """Runs in which an AWS answer changed its fields (a field that every resource had is gone, or a new one appeared)."""
        since = naive_utc(now()) - timedelta(days=max(1, min(days, 365)))
        rows = [{"scan_id": s["scan_id"], "started_at": s["started_at"], "changes": s["summary"]["shape_changes"]}
                for s in deps.store.coll("scans").find({"started_at": {"$gte": since}, "summary.shape_changes.0": {"$exists": True}},
                                                       {"scan_id": 1, "started_at": 1, "summary.shape_changes": 1}).sort("started_at", -1).limit(30)]
        return iso({"scans": rows, "count": sum(len(r["changes"]) for r in rows)})

    # ------------------------------------------------------------------ notifications and retention (settings page)
    def need_notifier() -> Notifier:
        if deps.notifier is None:
            raise HTTPException(503, "알림을 쓸 수 없습니다")
        return deps.notifier

    @app.get("/api/settings/notify", dependencies=[api])
    def get_notify() -> dict:
        return need_notifier().view()

    @app.put("/api/settings/notify", dependencies=[api])
    def put_notify(body: NotifySettings, request: Request) -> dict:
        n, user = need_notifier(), who(request)
        n.save(body, user, now())
        deps.state.audit(user, "notify_settings", body.model_dump(), now())
        return n.view()

    @app.post("/api/settings/notify/test", dependencies=[api])
    def test_notify(request: Request) -> dict:
        ok, message = need_notifier().test()
        deps.state.audit(who(request), "notify_test", {"ok": ok}, now())
        return {"ok": ok, "message": message}

    @app.get("/api/settings/retention", dependencies=[api])
    def get_retention() -> dict:
        cfg_r = retention_mod.load(deps.store)
        meta = deps.store.coll("runtime").find_one({"_id": "retention_meta"}) or {}
        return iso({**cfg_r.model_dump(), "limits": [retention_mod.MIN_DAYS, retention_mod.MAX_DAYS], "keep_scans": retention_mod.KEEP_SCANS,
                    "last_run": meta.get("last_run"), "last_removed": meta.get("removed"),
                    "preview": retention_mod.preview(deps.store, cfg_r, now())})

    @app.put("/api/settings/retention", dependencies=[api])
    def put_retention(body: RetentionSettings, request: Request) -> dict:
        user = who(request)
        retention_mod.save(deps.store, body, user, now())
        deps.state.audit(user, "retention_settings", body.model_dump(), now())
        return get_retention()

    @app.post("/api/settings/retention/run", dependencies=[api])
    def run_retention(body: RetentionRunBody, request: Request) -> dict:
        """Delete now what the saved periods say. Needs ``confirm`` (the page shows how much first)."""
        cfg_r = retention_mod.load(deps.store)
        if not cfg_r.enabled:
            raise HTTPException(409, "보관 기간 정리가 꺼져 있습니다. 먼저 켜고 저장하세요")
        if not body.confirm:
            raise HTTPException(409, {"code": "CONFIRM_NEEDED", "preview": iso(retention_mod.preview(deps.store, cfg_r, now())),
                                      "message": "정리할 양을 확인한 뒤 다시 요청하세요"})
        removed = retention_mod.purge(deps.store, cfg_r, now())
        deps.state.audit(who(request), "retention_run", {"removed": removed}, now())
        deps.store.coll("runtime").update_one({"_id": "retention_meta"}, {"$set": {"last_run": naive_utc(now()), "removed": removed}}, upsert=True)
        return {"removed": removed}

    # ------------------------------------------------------------------ concurrency and change log
    @app.get("/api/settings/concurrency", dependencies=[api])
    def get_concurrency() -> dict:
        return deps.state.concurrency(deps.settings.concurrency).model_dump()

    @app.put("/api/settings/concurrency", dependencies=[api])
    def put_concurrency(body: ConcurrencyUpdate, request: Request) -> dict:
        return deps.state.set_concurrency(body, who(request), now()).model_dump()

    @app.get("/api/audit", dependencies=[api])
    def audit(limit: int = 50) -> dict:
        return {"entries": iso(deps.state.recent_audit(max(1, min(limit, 200))))}

    return app
