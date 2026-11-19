"""What changed in the collected resources: new, changed and deleted ones, and for a change the fields that differ.

Built from what the collector already keeps: ``resource_history`` holds the previous copy of a resource each time its
configuration changed, ``resources`` holds the current copy (``first_seen``, ``deleted_at``). Volatile fields (see
``storage/volatile.py``) are left out of the comparison, like they are of the change hash.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from bson import ObjectId
from bson.errors import InvalidId

from cspm_collector.storage.normalize import unescape_keys
from cspm_collector.storage.store import Store
from cspm_collector.storage.volatile import stable_view

KINDS = ("changed", "created", "deleted")
FIRST_SCAN_GRACE = timedelta(hours=1)  # resources first seen within this of the first one of their account+item are "the first collection"
MAX_DIFF_LINES = 200
MAX_VALUE_CHARS = 400
MAX_CONFIG_CHARS = 120_000  # the configuration of one resource shown as text; more is cut (the data stays in the database)
MAX_HISTORY = 30


def _clip(value):
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + "…"


def diff_values(old, new, path: str = "", out: list[dict] | None = None) -> list[dict]:
    """Differences between two JSON-like values as ``{"path", "kind": added|removed|changed, "before", "after"}``."""
    out = [] if out is None else out
    if len(out) >= MAX_DIFF_LINES:
        return out
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new), key=str):
            sub = f"{path}.{key}" if path else str(key)
            if key not in old:
                out.append({"path": sub, "kind": "added", "before": None, "after": _clip(new[key])})
            elif key not in new:
                out.append({"path": sub, "kind": "removed", "before": _clip(old[key]), "after": None})
            else:
                diff_values(old[key], new[key], sub, out)
    elif isinstance(old, list) and isinstance(new, list):
        if all(not isinstance(x, (dict, list)) for x in [*old, *new]):  # plain values: compare as sets, order is not a change
            for v in [x for x in old if x not in new]:
                out.append({"path": path, "kind": "removed", "before": _clip(v), "after": None})
            for v in [x for x in new if x not in old]:
                out.append({"path": path, "kind": "added", "before": None, "after": _clip(v)})
        else:
            for i in range(max(len(old), len(new))):
                sub = f"{path}[{i}]"
                if i >= len(old):
                    out.append({"path": sub, "kind": "added", "before": None, "after": _clip(new[i])})
                elif i >= len(new):
                    out.append({"path": sub, "kind": "removed", "before": _clip(old[i]), "after": None})
                else:
                    diff_values(old[i], new[i], sub, out)
    elif old != new:
        out.append({"path": path or "(value)", "kind": "changed", "before": _clip(old), "after": _clip(new)})
    return out


def _view(service: str, rtype: str, config, tags) -> dict:
    return {"config": stable_view(service, rtype, config) if isinstance(config, dict) else config, "tags": tags}


def _stored(doc: dict, store: Store | None = None):
    """Config of a ``resources`` / ``resource_history`` document in its original (unescaped) form."""
    if store is not None and doc.get("config_chunks"):
        return store.get_config(doc)
    config = doc.get("config")
    return unescape_keys(config) if doc.get("key_escaped") else config


def _event(kind: str, doc: dict, at: datetime, scan_id: str | None, ident: str) -> dict:
    return {"id": ident, "key": doc.get("resource_key") or doc.get("_id"), "kind": kind, "at": at, "account_id": doc.get("account_id"), "region": doc.get("region"),
            "service": doc.get("service"), "resource_type": doc.get("resource_type"), "resource_id": doc.get("resource_id"),
            "arn": doc.get("arn"), "scan_id": scan_id}


def recent_changes(store: Store, now: datetime, days: int = 7, kinds: tuple[str, ...] = KINDS, service: str | None = None,
                   account_id: str | None = None, text: str | None = None, limit: int = 200) -> list[dict]:
    """Newest first. ``text``: part of a resource id or ARN."""
    since = now - timedelta(days=max(1, min(days, 365)))
    limit = max(1, min(limit, 500))
    base = {}
    if service:
        base["service"] = service
    if account_id:
        base["account_id"] = account_id
    events: list[dict] = []

    def matches(doc: dict) -> bool:
        return not text or text.lower() in f"{doc.get('resource_id', '')} {doc.get('arn') or ''}".lower()

    if "changed" in kinds:
        for h in store.coll("resource_history").find({**base, "changed_at": {"$gte": since}}).sort("changed_at", -1).limit(limit * 3):
            if matches(h):
                events.append(_event("changed", h, h["changed_at"], h.get("changed_in_scan"), f"h:{h['_id']}"))
    if "deleted" in kinds:
        for d in store.coll("resources").find({**base, "deleted_at": {"$gte": since}}).sort("deleted_at", -1).limit(limit * 3):
            if matches(d):
                events.append(_event("deleted", d, d["deleted_at"], d.get("scan_id"), f"r:{d['_id']}"))
    if "created" in kinds:
        first: dict[tuple, datetime | None] = {}

        def baseline(d: dict):
            pair = (d.get("account_id"), d.get("service"))
            if pair not in first:
                row = store.coll("resources").find({"account_id": pair[0], "service": pair[1]}, {"first_seen": 1}).sort("first_seen", 1).limit(1)
                first[pair] = next(iter(row), {}).get("first_seen")
            return first[pair]

        for d in store.coll("resources").find({**base, "first_seen": {"$gte": since}}).sort("first_seen", -1).limit(limit * 3):
            start = baseline(d)
            if matches(d) and start is not None and d["first_seen"] > start + FIRST_SCAN_GRACE:
                events.append(_event("created", d, d["first_seen"], d.get("scan_id"), f"r:{d['_id']}"))
    events.sort(key=lambda e: e["at"], reverse=True)
    return events[:limit]


def change_detail(store: Store, ident: str) -> dict | None:
    """The details of one event: for a change the differing fields, for a new or deleted resource a few facts."""
    kind, _, raw = ident.partition(":")
    if kind == "h":
        try:
            old = store.coll("resource_history").find_one({"_id": ObjectId(raw)})
        except (InvalidId, TypeError):
            return None
        if old is None:
            return None
        key = old["resource_key"]
        newer = store.coll("resource_history").find_one({"resource_key": key, "changed_at": {"$gt": old["changed_at"]}},
                                                         sort=[("changed_at", 1)])
        current = newer or store.coll("resources").find_one({"_id": key})
        out = {**_event("changed", old, old["changed_at"], old.get("changed_in_scan"), ident),
               "previous_scan": old.get("version_scan_id"), "truncated": bool(old.get("config_truncated"))}
        if old.get("config_truncated"):
            return {**out, "diff": [], "note": "설정이 너무 커서 이전 값이 보관되지 않았습니다 (변경 시각만 알 수 있습니다)"}
        if current is None:
            return {**out, "diff": [], "note": "현재 값을 찾을 수 없습니다"}
        before = _view(old["service"], old["resource_type"], _stored(old), _unesc(old, "tags"))
        after = _view(old["service"], old["resource_type"], _stored(current, store), _unesc(current, "tags"))
        diff = diff_values(before, after)
        return {**out, "diff": diff, "capped": len(diff) >= MAX_DIFF_LINES,
                "note": None if diff else "설정 값은 같고 수집 때마다 바뀌는 항목(마지막 사용 시각 등)만 달랐습니다"}
    if kind == "r":
        doc = store.coll("resources").find_one({"_id": raw})
        if doc is None:
            return None
        deleted = doc.get("deleted_at") is not None
        out = _event("deleted" if deleted else "created", doc, doc["deleted_at"] if deleted else doc["first_seen"], doc.get("scan_id"), ident)
        return {**out, "diff": [], "tags": _unesc(doc, "tags"), "first_seen": doc.get("first_seen"), "last_seen": doc.get("last_seen"),
                "note": "수집에서 더 이상 보이지 않아 삭제로 표시되었습니다" if deleted else "처음 수집된 리소스입니다"}
    return None


def resource_detail(store: Store, key: str) -> dict | None:
    """One resource as it is stored now (facts, tags, configuration as text) and the times it changed, newest first."""
    doc = store.coll("resources").find_one({"_id": key})
    if doc is None:
        return None
    config = _stored(doc, store)
    text = json.dumps(config, ensure_ascii=False, indent=2, default=str, sort_keys=True) if config is not None else ""
    history = [{"id": f"h:{h['_id']}", "at": h["changed_at"], "scan_id": h.get("changed_in_scan"), "truncated": bool(h.get("config_truncated"))}
               for h in store.coll("resource_history").find({"resource_key": key}).sort("changed_at", -1).limit(MAX_HISTORY)]
    return {"key": key, "account_id": doc.get("account_id"), "region": doc.get("region"), "service": doc.get("service"),
            "resource_type": doc.get("resource_type"), "resource_id": doc.get("resource_id"), "arn": doc.get("arn"),
            "tags": _unesc(doc, "tags"), "first_seen": doc.get("first_seen"), "last_seen": doc.get("last_seen"), "deleted_at": doc.get("deleted_at"),
            "config_text": text[:MAX_CONFIG_CHARS], "config_cut": len(text) > MAX_CONFIG_CHARS, "history": history}


def _unesc(doc: dict, field: str):
    value = doc.get(field)
    return unescape_keys(value) if doc.get("key_escaped") else value
