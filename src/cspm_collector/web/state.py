"""What the control page persists: schedules, concurrency settings, change log and the scheduler lease."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field
from pymongo.errors import DuplicateKeyError

from cspm_collector.core.config import ConcurrencySettings
from cspm_collector.storage.store import Store

from .schedule import Schedule, next_run


class ConcurrencyUpdate(BaseModel):
    """Bounds keep a typo from hammering an AWS account or stalling the collector."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(ge=1, le=128)
    per_account: int = Field(ge=1, le=64)
    per_service: int = Field(ge=1, le=32)
    per_resource: int = Field(ge=1, le=64)


def naive_utc(dt: datetime) -> datetime:
    """MongoDB stores naive UTC."""
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def aware_utc(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None else None


class WebState:
    def __init__(self, store: Store, tz: ZoneInfo):
        self.store, self.tz = store, tz

    # ------------------------------------------------------------------ schedules
    def schedules(self) -> dict[str, dict]:
        return {d["_id"]: d for d in self.store.coll("schedules").find({})}

    def set_schedule(self, service: str, schedule: Schedule, auto: bool, user: str, now: datetime,
                     target: dict | None = None) -> dict:
        """Save one item's schedule. ``auto`` is the "collect automatically" checkbox; ``target`` is the account
        selection ({"accounts": [...], "account_groups": [...]}, empty = all accounts)."""
        nxt = next_run(schedule, now.astimezone(self.tz)) if auto else None
        doc = {"auto": auto, "schedule": schedule.model_dump(), "updated_at": naive_utc(now), "updated_by": user,
               "next_run": naive_utc(nxt) if nxt else None, "target": target or {"accounts": [], "account_groups": []}}
        self.store.coll("schedules").update_one({"_id": service}, {"$set": doc}, upsert=True)
        self.audit(user, "schedule", {"service": service, "auto": auto, "schedule": schedule.model_dump(),
                                      "target": doc["target"]}, now)
        return {"_id": service, **doc}

    def due(self, now: datetime) -> list[dict]:
        return list(self.store.coll("schedules").find({"auto": True, "next_run": {"$lte": naive_utc(now)}}))

    def mark_triggered(self, service: str, now: datetime, nxt: datetime | None, scan_id: str | None,
                       skipped: str | None) -> None:
        self.store.coll("schedules").update_one({"_id": service}, {"$set": {
            "last_triggered_at": naive_utc(now), "last_scan_id": scan_id, "last_skip": skipped,
            "next_run": naive_utc(nxt) if nxt else None}})

    # ------------------------------------------------------------------ concurrency
    def concurrency(self, default: ConcurrencySettings) -> ConcurrencySettings:
        doc = self.store.coll("settings").find_one({"_id": "concurrency"})
        if not doc:
            return default
        return ConcurrencySettings(**{k: doc[k] for k in ConcurrencySettings.model_fields if k in doc})

    def set_concurrency(self, values: ConcurrencyUpdate, user: str, now: datetime) -> ConcurrencySettings:
        self.store.coll("settings").update_one(
            {"_id": "concurrency"}, {"$set": {**values.model_dump(), "updated_at": naive_utc(now), "updated_by": user}},
            upsert=True)
        self.audit(user, "concurrency", values.model_dump(), now)
        return ConcurrencySettings(**values.model_dump())

    # ------------------------------------------------------------------ change log
    def audit(self, user: str, action: str, detail: dict, now: datetime) -> None:
        self.store.coll("audit").insert_one({"at": naive_utc(now), "user": user, "action": action, "detail": detail})

    def recent_audit(self, limit: int = 50) -> list[dict]:
        return list(self.store.coll("audit").find({}, {"_id": 0}).sort("at", -1).limit(limit))

    # ------------------------------------------------------------------ scheduler lease
    def acquire_lease(self, owner: str, ttl_seconds: int, now: datetime) -> bool:
        """Only one server may fire schedules. The holder renews the lease every tick; if it dies the lease
        expires and another instance takes over."""
        coll = self.store.coll("runtime")
        expires = naive_utc(now) + timedelta(seconds=ttl_seconds)
        try:
            res = coll.update_one(
                {"_id": "scheduler", "$or": [{"owner": owner}, {"expires_at": {"$lt": naive_utc(now)}}]},
                {"$set": {"owner": owner, "expires_at": expires}}, upsert=True)
        except DuplicateKeyError:  # the document exists and belongs to a live holder
            return False
        return bool(res.matched_count or res.upserted_id)
