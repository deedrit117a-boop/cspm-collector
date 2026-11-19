"""Notice when the shape of an AWS answer changes: a field that every resource of a type used to have is gone (or a new one is there).

A service that renames or drops a field makes the stored data quietly poorer, and nothing fails. The names of the fields of
every resource type are remembered (collection ``runtime``, one document per type); after a complete run they are compared with
the run's own. Only the *names* are looked at, never values.

Noise is kept down on purpose: a type is only compared when it had ``MIN_RESOURCES`` resources in both runs and the run saw at
least half as many as the one before (a run of a few accounts must not look like "a field disappeared").
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from cspm_collector.storage.store import Store

MIN_RESOURCES = 5
MAX_CHANGES = 50


def field_names(config: dict) -> set[str]:
    """Top-level field names of a stored config, and for ``_details`` the name of each detail API and its top-level fields."""
    names = set()
    for key, value in config.items():
        if key in ("_errors",):
            continue
        if key == "_details" and isinstance(value, dict):
            for api, detail in value.items():
                names.add(f"_details.{api}")
                if isinstance(detail, dict):
                    names.update(f"_details.{api}.{k}" for k in detail)
            continue
        names.add(key)
    return names


class ShapeTracker:
    """Collects the field names seen in one run, then compares them with what was seen before."""

    def __init__(self) -> None:
        self.names: dict[tuple[str, str], set[str]] = defaultdict(set)
        self.counts: dict[tuple[str, str], int] = defaultdict(int)

    def add(self, records) -> None:
        for r in records:
            key = (r.service, r.resource_type)
            self.names[key] |= field_names(r.config)
            self.counts[key] += 1

    def finish(self, store: Store, now: datetime) -> list[dict]:
        """Compare with the remembered shapes, remember the new ones, return the changes (``added`` / ``removed`` names)."""
        coll, changes = store.coll("runtime"), []
        for (service, rtype), seen in sorted(self.names.items()):
            n, _id = self.counts[(service, rtype)], f"shape:{service}:{rtype}"
            if n < MIN_RESOURCES:
                continue
            before = coll.find_one({"_id": _id})
            if before is not None and before.get("count", 0) >= MIN_RESOURCES and n * 2 >= before["count"]:
                old = set(before.get("names") or [])
                added, removed = sorted(seen - old), sorted(old - seen)
                if added or removed:
                    changes.append({"service": service, "resource_type": rtype, "count": n, "added": added[:20], "removed": removed[:20]})
            elif before is not None and before.get("count", 0) >= MIN_RESOURCES:
                continue  # a much smaller sample: neither compare nor overwrite the remembered shape
            coll.update_one({"_id": _id}, {"$set": {"names": sorted(seen), "count": n, "updated_at": now}}, upsert=True)
        return changes[:MAX_CHANGES]
