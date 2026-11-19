"""Spec-driven collector. Subclasses override the small hooks for service quirks."""
from __future__ import annotations

import copy
import hashlib
import json
import threading
from datetime import timezone
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from cspm_collector.core.call import CallResult, call_api
from cspm_collector.core.errors import Status
from cspm_collector.spec.schema import ApiSpec
from cspm_collector.storage.normalize import normalize
from cspm_collector.storage.records import ResourceRecord, StatusRecord, now_utc

from .base import CollectContext, CollectResult, Collector, register
from .masking import apply_mask
from .paths import extract, merge_pages

# Failure statuses ordered by how much attention they deserve when several calls disagree.
_PRIORITY = [Status.ACCESS_DENIED, Status.THROTTLED_GIVEUP, Status.TIMEOUT, Status.ERROR,
             Status.NOT_ENABLED, Status.NOT_SUPPORTED]
_FALLBACK_IDS = ("Id", "ID", "Name", "Arn", "ARN")


@dataclass
class Entry:
    """One resource being assembled: the list item plus everything fetched for it."""

    item: dict
    rid: str
    details: dict = field(default_factory=dict)  # api name -> response (None = "no such configuration")
    errors: dict = field(default_factory=dict)  # api name -> error code
    findings: list = field(default_factory=list)  # secret findings (location/type only)
    extra: dict = field(default_factory=dict)
    reused: bool = False  # the details come from the stored copy (the change marker did not move)


class _Agg:
    """Folds many calls of one API into a single collection_status row."""

    def __init__(self) -> None:
        self.calls = self.ok = self.count = self.api_calls = 0
        self.duration_ms = 0.0
        self.failures: Counter = Counter()
        self.first_error: tuple[str | None, str | None] = (None, None)

    def add(self, res: CallResult, count: int = 0) -> None:
        self.calls += 1
        self.duration_ms += res.duration_ms
        self.api_calls += res.api_calls
        if res.ok:
            self.ok += 1
            self.count += count
        else:
            self.failures[res.status] += 1
            self.first_error = self.first_error if self.first_error[0] else (res.error_code, res.error_message)

    def status(self) -> Status:
        for s in _PRIORITY:
            if self.failures[s]:
                return s
        return Status.SUCCESS


def _naive(dt):
    """MongoDB hands back naive UTC datetimes; compare like with like."""
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo is not None else dt


def _render(value: Any, ctx: CollectContext) -> Any:
    """Substitute ``{account_id}`` / ``{region}`` in spec parameters."""
    if isinstance(value, str):
        return value.replace("{account_id}", ctx.account_id).replace("{region}", ctx.aws_region)
    if isinstance(value, dict):
        return {k: _render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v, ctx) for v in value]
    return value


@register("generic")
class GenericCollector(Collector):
    # ------------------------------------------------------------------ hooks
    def client_for(self, api: ApiSpec, entry: Entry | None):
        return self.ctx.client(api.client)

    def handled_elsewhere(self, api: ApiSpec) -> bool:
        """True for spec APIs the subclass calls itself (in ``after_roots``)."""
        return False

    def prepare_entries(self, root: ApiSpec, entries: list[Entry]) -> None:
        """Called right after a root API returned (e.g. to look up per-bucket regions)."""

    def enrich(self, root: ApiSpec, entry: Entry) -> None:
        """Called per entry after the spec's dependent APIs ran (second-level lookups)."""

    def sanitize_detail(self, api: ApiSpec, value: Any, entry: Entry) -> Any:
        """Mask secrets in a dependent response (spec ``mask`` rules); hits are appended to ``entry.findings``."""
        if value:
            for rule in api.mask:
                entry.findings += apply_mask(value, rule, f"{self.ctx.service.service}.{entry.rid}.{api.key}")
        return value

    @staticmethod
    def _detail_path(entry: Entry, spec: str):
        """Follow ``"<detail key>.<dotted path>"`` (digits index into lists) inside ``entry.details``."""
        key, _, path = spec.partition(".")
        node = entry.details.get(key)
        for part in filter(None, path.split(".")):
            if isinstance(node, dict):
                node = node.get(part)
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                return None
        return node

    def arn_for(self, root: ApiSpec, entry: Entry) -> str | None:
        if root.arn_from:
            return self._detail_path(entry, root.arn_from)
        if root.arn_field:
            return entry.item.get(root.arn_field)
        return entry.item.get("Arn") or entry.item.get("ARN")

    def tags_for(self, root: ApiSpec, entry: Entry):
        if root.tags_from:  # "TagDescriptions.0.Tags": digits index into lists
            return self._detail_path(entry, root.tags_from)
        item = entry.item
        return item.get("Tags") or item.get("TagList") or item.get("TagSet") or item.get("tags")

    def sanitize_item(self, root: ApiSpec, entry: Entry) -> None:
        """Mask secrets inside the list item itself: the spec's ``mask`` rules (subclasses may add more)."""
        for rule in root.mask:
            entry.findings += apply_mask(entry.item, rule, f"{self.ctx.service.service}.{entry.rid}")

    def resource_id(self, root: ApiSpec, item: dict, parent: Entry | None = None) -> str:
        rid = self._base_id(root, item)
        return f"{parent.rid}|{rid}" if parent is not None and root.scope_id_to_parent else rid

    def _base_id(self, root: ApiSpec, item: dict) -> str:
        if root.id_field and "+" in root.id_field:
            parts = [str(item[f]) for f in root.id_field.split("+") if item.get(f) not in (None, "")]
            if parts:
                return "|".join(parts)
        elif root.id_field and item.get(root.id_field) not in (None, ""):
            return str(item[root.id_field])
        for key in _FALLBACK_IDS:
            if item.get(key):
                return str(item[key])
        return hashlib.sha1(json.dumps(item, sort_keys=True, default=str).encode()).hexdigest()[:16]

    # ------------------------------------------------------------------ plumbing
    def call(self, api: ApiSpec | str, params: dict | None = None, client=None, *, paginate: bool | None = None,
             count: Callable[[CallResult], int] | None = None) -> CallResult:
        spec = api if isinstance(api, ApiSpec) else None
        name = spec.key if spec else api
        if client is None:
            client = self.client_for(spec, None) if spec else self.ctx.client()
        if paginate is None:
            paginate = spec.paginate if spec else False
        api_name = spec.api if spec else api
        res = call_api(client, self.ctx.service.service, api_name, params or {}, paginate=paginate,
                       stats=self.ctx.stats, bucket=self.ctx.bucket)
        with self._lock:
            self._aggs[name].add(res, count(res) if count and res.ok else 0)
        return res

    def _pmap(self, fn: Callable, items: list) -> list:
        def safe(x):
            try:
                return fn(x)
            except Exception as exc:  # noqa: BLE001 - a bug in one resource must not kill the service
                with self._lock:
                    self._aggs["_internal"].failures[Status.ERROR] += 1
                    self._aggs["_internal"].first_error = (type(exc).__name__, str(exc))
                return None

        return list(self._pool.map(safe, items))

    # ------------------------------------------------------------------ main
    def collect(self, ctx: CollectContext) -> CollectResult:
        self.ctx = ctx
        self._lock = threading.Lock()
        self._aggs: dict[str, _Agg] = defaultdict(_Agg)
        self._skipped: dict[str, str] = {}
        # helper calls a subclass makes outside the spec: name -> (resource_type, affects_sweep)
        self._extra_meta: dict[str, tuple[str | None, bool]] = {}
        self.result = CollectResult()
        apis = [a for a in ctx.service.apis]
        runnable = []
        for a in apis:
            if ctx.options.enabled(a.opt_in_flag):
                runnable.append(a)
            else:
                self._skipped[a.key] = f"opt-in flag {a.opt_in_flag} not set"
        children: dict[str, list[ApiSpec]] = defaultdict(list)
        for a in runnable:
            if a.depends_on:
                children[a.depends_on.api].append(a)  # depends_on points at the parent's key

        with ThreadPoolExecutor(max_workers=ctx.options.per_resource_workers, thread_name_prefix="res") as pool:
            self._pool = pool
            for root in runnable:
                if root.depends_on is None and not self.handled_elsewhere(root):
                    self._run_root(root, children)
            self.after_roots()
        self._finish(apis)
        return self.result

    def after_roots(self) -> None:
        """Hook for collectors with extra top-level work (IAM credential report)."""

    def _run_root(self, root: ApiSpec, children: dict[str, list[ApiSpec]]) -> None:
        ctx = self.ctx
        res = self.call(root, _render(root.parameters, ctx))
        if not res.ok:
            return
        if root.setting:
            value = None if res.empty else (extract(res.pages, root.result_path) if root.result_path else merge_pages(res.pages))
            self.result.settings.append((root.setting, value))
            self._aggs[root.key].count += 0 if res.empty else 1
            return

        items = extract(res.pages, root.result_path) if root.result_path else (
            [] if res.empty else [merge_pages(res.pages)])
        items = [i if isinstance(i, dict) else {"Value": i} for i in items]  # e.g. detector ids, queue urls
        entries = [Entry(item=i, rid=self.resource_id(root, i) if root.result_path else ctx.account_id)
                   for i in items]
        with self._lock:
            self._aggs[root.key].count = len(entries)
        self.prepare_entries(root, entries)
        for e in entries:
            self.sanitize_item(root, e)
        self._reuse_stored(root, entries)
        produced: list[tuple[ApiSpec, Entry]] = []
        self._expand(root, entries, children, produced)
        self._pmap(lambda e: self.enrich(root, e), entries)
        self.result.resources.extend(self._record(api, e) for api, e in produced)

    def _reuse_stored(self, root: ApiSpec, entries: list[Entry]) -> None:
        """Items with a ``change_marker``: where the marker equals the stored copy's (and the copy was read in full recently),
        take the stored details instead of calling the detail APIs again. Anything doubtful is read in full."""
        marker, ctx = root.change_marker, self.ctx
        if not marker or not entries:
            return
        stored = {}
        if ctx.previous is not None and ctx.reuse_since is not None:
            try:
                stored = ctx.previous(root.resource_type or root.api)
            except Exception:  # noqa: BLE001 - the shortcut is optional: read in full
                stored = {}
        since = _naive(ctx.reuse_since) if ctx.reuse_since is not None else None
        checked = _naive(now_utc())
        for e in entries:
            old = stored.get(e.rid)
            cfg = (old or {}).get("config") or {}
            current = e.item.get(marker)
            fresh = old is not None and old.get("detail_checked_at") is not None and _naive(old["detail_checked_at"]) >= since
            if (fresh and current is not None and "_details" in cfg and not cfg.get("_errors")
                    and normalize(current) == cfg.get(marker)):
                e.details, e.reused = copy.deepcopy(cfg["_details"]), True
                e.extra["detail_checked_at"] = old["detail_checked_at"]
                self.result.reused += 1
            else:
                e.extra["detail_checked_at"] = checked

    def _expand(self, api: ApiSpec, entries: list[Entry], children: dict[str, list[ApiSpec]],
                produced: list[tuple[ApiSpec, Entry]]) -> None:
        """Run the dependents of ``api``: details attach to the entries, as_resource items become new entries
        that may have dependents of their own (load balancer -> listener -> rule)."""
        produced.extend((api, e) for e in entries)
        for child in children.get(api.key, []):
            new = self._run_children(child, api, entries)
            if new is not None:
                self._expand(child, new, children, produced)

    def _run_children(self, child: ApiSpec, parent_api: ApiSpec, parents: list[Entry]) -> list[Entry] | None:
        dep = child.depends_on

        def one(parent: Entry) -> list[Entry]:
            if parent.reused and not child.as_resource:
                return []  # its details were taken from the stored copy
            params = _render(child.parameters, self.ctx)
            for param, field_name in dep.params.items():
                if parent.item.get(field_name) is None:
                    return []
                if param.endswith("[]"):  # the API wants a list: "Ids[]: Id" sends Ids=[item["Id"]]
                    params[param[:-2]] = [parent.item[field_name]]
                else:
                    params[param] = parent.item[field_name]
            client = self.client_for(child, parent)
            if child.as_resource:
                res = self.call(child, params, client)
                if not res.ok:
                    parent.errors[child.key] = res.error_code
                    return []
                made = []
                for item in extract(res.pages, child.result_path):
                    item = item if isinstance(item, dict) else {"Value": item}
                    e = Entry(item=item, rid=self.resource_id(child, item, parent))
                    e.extra = {name: parent.item.get(field) for name, field in child.inherit.items()}
                    e.extra["parent"] = {"resource_type": parent_api.resource_type, "resource_id": parent.rid}
                    self.sanitize_item(child, e)
                    made.append(e)
                with self._lock:
                    self._aggs[child.key].count += len(made)
                return made

            res = self.call(child, params, client, count=lambda r: 0 if r.empty else 1)
            if not res.ok:
                parent.errors[child.key] = res.error_code
                return []
            value = None if res.empty else merge_pages(res.pages)
            parent.details[child.key] = self.sanitize_detail(child, value, parent)
            return []

        results = self._pmap(one, parents)
        return [e for r in results if r for e in r] if child.as_resource else None

    def _record(self, root: ApiSpec, entry: Entry) -> ResourceRecord:
        config = dict(entry.item)
        if entry.details:
            config["_details"] = entry.details
        if entry.errors:
            config["_errors"] = entry.errors
        extra = dict(entry.extra)
        if entry.findings:  # the same value can be seen in the list item and in a detail response
            extra["secret_findings"] = [dict(t) for t in sorted({tuple(sorted(f.items())) for f in entry.findings})]
        return ResourceRecord(
            account_id=self.ctx.account_id, region=self.ctx.region, service=self.ctx.service.service,
            resource_type=root.resource_type or root.api, resource_id=entry.rid, config=config,
            arn=self.arn_for(root, entry), tags=self.tags_for(root, entry), extra=extra,
        )

    def _finish(self, apis: list[ApiSpec]) -> None:
        ctx = self.ctx
        detail_keys = {a.key for a in apis if a.depends_on and not a.as_resource}
        for a in apis:
            base = dict(account_id=ctx.account_id, region=ctx.region, service=ctx.service.service, api=a.key,
                        resource_type=a.resource_type,
                        affects_sweep=a.key not in detail_keys and not a.setting)
            if a.key in self._skipped:
                self.result.statuses.append(StatusRecord(**base, status=Status.SKIPPED, error=self._skipped[a.key]))
                continue
            agg = self._aggs.get(a.key)
            if agg is None:
                parent = a.depends_on.api if a.depends_on else None
                parent_agg = self._aggs.get(parent) if parent else None
                if parent_agg is not None and parent_agg.status() is not Status.SUCCESS:
                    self.result.statuses.append(StatusRecord(**base, status=Status.SKIPPED, error="parent API failed"))
                else:
                    self.result.statuses.append(StatusRecord(**base, status=Status.SUCCESS, resource_count=0))
                continue
            status = agg.status()
            err_code, err_msg = agg.first_error
            if status is not Status.SUCCESS and agg.calls > 1:
                err_msg = f"{sum(agg.failures.values())}/{agg.calls} calls failed; first: {err_msg}"
            self.result.statuses.append(StatusRecord(
                **base, status=status, resource_count=agg.count, error_code=err_code, error=err_msg,
                duration_ms=agg.duration_ms, api_calls=agg.api_calls))
        self._enablement(apis)
        declared = {a.key for a in apis}
        for name, agg in self._aggs.items():  # helper calls a collector made on its own (not in the spec)
            if name in declared or name == "_internal":
                continue
            code, msg = agg.first_error
            rtype, sweeps = self._extra_meta.get(name, (None, False))
            self.result.statuses.append(StatusRecord(
                ctx.account_id, ctx.region, ctx.service.service, name, agg.status(), resource_type=rtype,
                resource_count=agg.count, error_code=code, error=msg, duration_ms=agg.duration_ms,
                api_calls=agg.api_calls, affects_sweep=sweeps))
        internal = self._aggs.get("_internal")
        if internal and internal.failures:
            code, msg = internal.first_error
            self.result.statuses.append(StatusRecord(
                ctx.account_id, ctx.region, ctx.service.service, "_internal", Status.ERROR,
                error_code=code, error=msg, affects_sweep=False))

    def _enablement(self, apis: list[ApiSpec]) -> None:
        """Store "<service>_enablement": enabled=True/False when the probe API answered, None when it could not."""
        probe = self.ctx.service.enablement_api
        if not probe:
            return
        agg = self._aggs.get(probe)
        if agg is None:
            return
        status = agg.status()
        if status is Status.SUCCESS:
            enabled: bool | None = agg.count > 0
        elif status is Status.NOT_ENABLED:
            enabled = False
        else:
            enabled = None  # unknown: AccessDenied, throttled, ...
        self.result.settings.append((f"{self.ctx.service.service}_enablement",
                                     {"enabled": enabled, "status": status.value, "resources": agg.count}))
