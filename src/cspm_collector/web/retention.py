"""How long the collector keeps what it collected, and the clean-up that enforces it.

Four kinds of data, each with its own period (days; empty = keep forever). Off until someone turns it on.

* ``scans``      runs older than this: the run, its per-item status rows and its per-account results. The newest
                 ``KEEP_SCANS`` finished runs are always kept (the health pages read them).
* ``history``    earlier versions of resources (``resource_history``): the "what changed" data.
* ``deleted``    resources that were not seen any more for this long (and their relationships): the current copy is dropped.
* ``audit``      the change log of this page.

Resources that are still seen are never touched, whatever the periods. The clean-up only deletes inside the collector's own
collections.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from cspm_collector.storage.store import Store

KEEP_SCANS = 20
MIN_DAYS, MAX_DAYS = 7, 3650
CATEGORIES = ("scans", "history", "deleted", "audit")


class RetentionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    scans_days: int | None = Field(90, ge=MIN_DAYS, le=MAX_DAYS)
    history_days: int | None = Field(365, ge=MIN_DAYS, le=MAX_DAYS)
    deleted_days: int | None = Field(180, ge=MIN_DAYS, le=MAX_DAYS)
    audit_days: int | None = Field(365, ge=MIN_DAYS, le=MAX_DAYS)


def load(store: Store) -> RetentionSettings:
    doc = store.coll("settings").find_one({"_id": "retention"}) or {}
    return RetentionSettings(**{k: doc[k] for k in RetentionSettings.model_fields if k in doc})


def save(store: Store, values: RetentionSettings, user: str, now: datetime) -> RetentionSettings:
    store.coll("settings").update_one({"_id": "retention"}, {"$set": {**values.model_dump(), "updated_by": user,
                                                                      "updated_at": now.replace(tzinfo=None)}}, upsert=True)
    return values


def _victims(store: Store, cfg: RetentionSettings, now: datetime) -> dict[str, dict]:
    """For each category: the filter(s) of what would go, as ``{collection: filter}`` (empty when that period is not set)."""
    now = now.replace(tzinfo=None)
    plan: dict[str, dict] = {}
    if cfg.scans_days:
        cutoff = now - timedelta(days=cfg.scans_days)
        keep = [d["scan_id"] for d in store.coll("scans").find({"status": {"$ne": "RUNNING"}}, {"scan_id": 1})
                .sort("started_at", -1).limit(KEEP_SCANS)]
        old = [d["scan_id"] for d in store.coll("scans").find({"status": {"$ne": "RUNNING"}, "started_at": {"$lt": cutoff},
                                                                "scan_id": {"$nin": keep}}, {"scan_id": 1})]
        plan["scans"] = {"scans": {"scan_id": {"$in": old}}, "collection_status": {"scan_id": {"$in": old}},
                         "scan_accounts": {"scan_id": {"$in": old}}}
    if cfg.history_days:
        plan["history"] = {"resource_history": {"changed_at": {"$lt": now - timedelta(days=cfg.history_days)}}}
    if cfg.deleted_days:
        cutoff = now - timedelta(days=cfg.deleted_days)
        gone = {"deleted_at": {"$lt": cutoff}}
        plan["deleted"] = {"resources": gone, "akamai_raw": gone, "edges": gone}
    if cfg.audit_days:
        plan["audit"] = {"audit": {"at": {"$lt": now - timedelta(days=cfg.audit_days)}}}
    return plan


def preview(store: Store, cfg: RetentionSettings, now: datetime) -> dict:
    """How much each category holds now and how much of it the periods would remove (nothing is deleted)."""
    now_naive = now.replace(tzinfo=None)
    out = {}
    plan = _victims(store, cfg, now)
    totals = {"scans": ("scans", {}), "history": ("resource_history", {}), "deleted": ("resources", {"deleted_at": {"$ne": None}}),
              "audit": ("audit", {})}
    for cat in CATEGORIES:
        coll, flt = totals[cat]
        total = store.coll(coll).count_documents(flt)
        victims = sum(store.coll(c).count_documents(f) for c, f in (plan.get(cat) or {}).items() if c == coll)
        oldest_field = {"scans": "started_at", "history": "changed_at", "deleted": "deleted_at", "audit": "at"}[cat]
        first = store.coll(coll).find(flt, {oldest_field: 1}).sort(oldest_field, 1).limit(1)
        oldest = next(iter(first), {}).get(oldest_field)
        out[cat] = {"total": total, "remove": victims, "oldest": oldest,
                    "oldest_days": round((now_naive - oldest).total_seconds() / 86400) if oldest else None}
    return out


def purge(store: Store, cfg: RetentionSettings, now: datetime) -> dict[str, int]:
    """Delete what the periods say. Returns the number of documents removed per collection."""
    removed: dict[str, int] = {}
    for _, parts in _victims(store, cfg, now).items():
        for coll, flt in parts.items():
            if coll == "resources":  # chunks of an oversized resource go with it
                ids = [d["_id"] for d in store.coll("resources").find(flt, {"_id": 1, "config_chunks": 1}) if d.get("config_chunks")]
                if ids:
                    store.coll("resource_chunks").delete_many({"resource_id": {"$in": ids}})
            n = store.coll(coll).delete_many(flt).deleted_count
            if n:
                removed[coll] = removed.get(coll, 0) + n
    return removed
