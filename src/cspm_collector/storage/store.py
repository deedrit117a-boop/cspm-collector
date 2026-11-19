"""MongoDB persistence: change-aware upserts, history, soft delete, status, indexes."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Iterable

from pymongo import ASCENDING, DESCENDING, ReplaceOne, UpdateOne
from pymongo.database import Database

from cspm_collector.core.config import MongoSettings

from .normalize import canonical_hash, escape_keys, hash_view, normalize, unescape_keys
from .records import ResourceRecord, SaveStats, StatusRecord, SweepScope, now_utc
from .volatile import stable_view, volatile_values

MANAGED_COLLECTIONS = (
    "scans", "collection_status", "resources", "resource_history", "resource_chunks",
    "account_settings", "akamai_raw", "scan_accounts", "edges",
    "schedules", "settings", "audit", "runtime", "groups",  # the control page: schedules, settings, change log, scheduler lease, user groups
)  # logical names; the real names carry MongoSettings.collection_prefix
META = "cspm_meta"
SCHEMA_VERSION = 1


def _normalize_tags(tags) -> list[dict] | None:
    """Tags as a key-sorted ``[{"key", "value"}]`` list, whatever shape the API used."""
    if tags is None:
        return None
    if isinstance(tags, dict):
        pairs = [(str(k), v) for k, v in tags.items()]
    else:
        pairs = [(str(t.get("Key", t.get("key", t.get("TagKey")))), t.get("Value", t.get("value", t.get("TagValue"))))
                 for t in tags]
    return [{"key": k, "value": v} for k, v in sorted(pairs, key=lambda kv: kv[0])]


class ForeignCollectionError(RuntimeError):
    """The target database already holds collections with our names that we did not create."""


class Store:
    def __init__(self, db: Database, settings: MongoSettings | None = None):
        self.db = db
        self.cfg = settings or MongoSettings()

    def coll(self, name: str):
        """The collection for a logical name ("resources", "scans", ...), with the configured prefix."""
        return self.db[self.cfg.collection_prefix + name]

    def managed_names(self) -> list[str]:
        return [self.cfg.collection_prefix + n for n in (*MANAGED_COLLECTIONS, META)]

    # ------------------------------------------------------------------ setup
    def init_db(self) -> None:
        """Refuse to touch a database that already contains same-named foreign collections."""
        existing = set(self.db.list_collection_names())
        meta = self.cfg.collection_prefix + META
        if meta not in existing:
            clash = sorted(existing & set(self.managed_names()))
            if clash:
                raise ForeignCollectionError(
                    f"database '{self.db.name}' already has collections {clash} that were not created by "
                    f"this collector; use another database, another collection_prefix, or rename them"
                )
            self.db[meta].insert_one({"_id": "schema", "version": SCHEMA_VERSION, "created_at": now_utc()})
        self.ensure_indexes()

    def ensure_indexes(self) -> None:
        c = self.coll
        c("scans").create_index([("scan_id", ASCENDING)], unique=True)
        c("collection_status").create_index([("scan_id", ASCENDING), ("account_id", ASCENDING),
                                             ("service", ASCENDING), ("region", ASCENDING)])
        c("collection_status").create_index([("scan_id", ASCENDING), ("status", ASCENDING)])
        c("resources").create_index([("account_id", ASCENDING), ("region", ASCENDING), ("service", ASCENDING),
                                     ("resource_type", ASCENDING), ("resource_id", ASCENDING)], unique=True)
        c("resources").create_index([("scan_id", ASCENDING), ("service", ASCENDING)])
        c("resources").create_index([("arn", ASCENDING)], sparse=True)
        c("resource_history").create_index([("resource_key", ASCENDING), ("changed_at", DESCENDING)])
        c("resource_chunks").create_index([("resource_id", ASCENDING), ("idx", ASCENDING)], unique=True)
        c("account_settings").create_index([("scan_id", ASCENDING), ("account_id", ASCENDING),
                                            ("region", ASCENDING), ("setting", ASCENDING)], unique=True)
        c("akamai_raw").create_index([("account_id", ASCENDING), ("service", ASCENDING), ("resource_type", ASCENDING),
                                      ("resource_id", ASCENDING)], unique=True)
        for f in ("hostnames", "edge_hostnames", "origin_hostnames", "scan_id", "property_id"):
            c("akamai_raw").create_index([(f, ASCENDING)])  # arrays -> multikey: join keys for the AWS graph
        c("scan_accounts").create_index([("scan_id", ASCENDING), ("account_id", ASCENDING)], unique=True)
        # edges: the sweep works per (account, region, service) of the source; readers follow src_key / dst_key (both are
        # ``resources._id`` / ``akamai_raw._id``) or look a pseudo node (hostname, ip) up by its type and id
        c("edges").create_index([("account_id", ASCENDING), ("region", ASCENDING), ("service", ASCENDING), ("resource_type", ASCENDING)])
        c("edges").create_index([("src_key", ASCENDING), ("rel", ASCENDING)])
        c("edges").create_index([("dst_key", ASCENDING)], sparse=True)
        c("edges").create_index([("dst_type", ASCENDING), ("dst_id", ASCENDING)])
        c("resource_history").create_index([("changed_at", ASCENDING)])  # the change list and the retention clean-up read by time
        for name in ("resources", "akamai_raw", "edges"):
            c(name).create_index([("deleted_at", ASCENDING)])
        c("schedules").create_index([("next_run", ASCENDING)])
        c("audit").create_index([("at", DESCENDING)])
        c("scans").create_index([("started_at", DESCENDING)])

    # ------------------------------------------------------------------ scans
    def create_scan(self, scan_id: str, accounts: list[str], spec_version: str,
                    prowler_version: str | None = None, options: dict | None = None) -> None:
        self.coll("scans").insert_one({
            "scan_id": scan_id, "status": "RUNNING", "started_at": now_utc(), "finished_at": None,
            "accounts": accounts, "spec_version": spec_version, "prowler_version": prowler_version,
            "options": options or {},
        })

    def update_progress(self, scan_id: str, done: int, total: int, running: list[str],
                        accounts: dict[str, dict] | None = None) -> None:
        """Live progress of a running scan (for the control page); cheap: one small update per finished task.
        ``accounts``: account id -> {"done", "total"} tasks, so the page can show every account's own progress."""
        progress = {"done": done, "total": total, "running": sorted(running), "updated_at": now_utc()}
        if accounts:
            progress["accounts"] = accounts
        self.coll("scans").update_one({"scan_id": scan_id}, {"$set": {"progress": progress}})

    def interrupt_stale_scans(self, older_than_minutes: int = 30, now: datetime | None = None) -> int:
        """Mark scans that say RUNNING but have not reported progress for a long time (their process died) as
        INTERRUPTED. Only silent ones: another server may legitimately be running a scan right now."""
        now = now or now_utc()
        cutoff = (now.replace(tzinfo=None) if now.tzinfo is None else now.astimezone(timezone.utc).replace(tzinfo=None))             - timedelta(minutes=older_than_minutes)
        res = self.coll("scans").update_many(
            {"status": "RUNNING", "$or": [{"progress.updated_at": {"$lt": cutoff}},
                                          {"progress": {"$exists": False}, "started_at": {"$lt": cutoff}}]},
            {"$set": {"status": "INTERRUPTED", "finished_at": now_utc()}})
        return res.modified_count

    def save_edges(self, scan_id: str, edges: list[dict], now: datetime | None = None) -> int:
        """Upsert the edges seen in this scan (see ``core/edges.py``); an edge that is seen again is revived."""
        if not edges:
            return 0
        now = now or now_utc()
        ops = [UpdateOne({"_id": e["_id"]}, {"$set": {**{k: v for k, v in e.items() if k != "_id"}, "scan_id": scan_id, "last_seen": now},
                                             "$unset": {"deleted_at": ""}}, upsert=True) for e in edges]
        for i in range(0, len(ops), self.cfg.batch_size):
            self.coll("edges").bulk_write(ops[i:i + self.cfg.batch_size], ordered=False)
        return len(ops)

    def save_scan_accounts(self, scan_id: str, per_account: dict[str, dict]) -> None:
        """What each account collected in a scan (tasks, resources, seconds, per-service numbers, status, error), one
        document per account: kept out of the scan document, which would otherwise grow with every account."""
        if not per_account:
            return
        docs = [{"scan_id": scan_id, "account_id": acct, **entry} for acct, entry in per_account.items()]
        self.coll("scan_accounts").delete_many({"scan_id": scan_id})
        self.coll("scan_accounts").insert_many(docs, ordered=False)

    def scan_accounts(self, scan_id: str) -> dict[str, dict]:
        """Per-account numbers of a scan (empty for scans of older versions, which kept them in ``summary.accounts``)."""
        return {d["account_id"]: {k: v for k, v in d.items() if k not in ("_id", "scan_id", "account_id")}
                for d in self.coll("scan_accounts").find({"scan_id": scan_id})}

    def finish_scan(self, scan_id: str, status: str, summary: dict | None = None) -> None:
        self.coll("scans").update_one(
            {"scan_id": scan_id},
            {"$set": {"status": status, "finished_at": now_utc(), "summary": summary or {}}},
        )

    # ------------------------------------------------------------------ resources
    def save_resources(self, scan_id: str, records: Iterable[ResourceRecord], now: datetime | None = None,
                       collection: str = "resources") -> SaveStats:
        """``collection`` is "resources" for AWS and "akamai_raw" for Akamai; history and chunks are shared."""
        now = now or now_utc()
        latest: dict[str, ResourceRecord] = {r.key: r for r in records}  # same key twice: last wins
        total = SaveStats()
        keys = list(latest)
        for i in range(0, len(keys), self.cfg.batch_size):
            total.add(self._save_batch(scan_id, [latest[k] for k in keys[i:i + self.cfg.batch_size]], now,
                                       self.coll(collection)))
        return total

    def _prepare(self, rec: ResourceRecord) -> dict:
        config = normalize(rec.config)
        tags = _normalize_tags(rec.tags)
        view = stable_view(rec.service, rec.resource_type, config)  # volatile fields out, unordered lists sorted
        digest = canonical_hash(hash_view({"config": view, "tags": tags}))
        volatile = volatile_values(rec.service, rec.resource_type, config)
        escaped = False
        if self.cfg.escape_keys:
            config, e1 = escape_keys(config)
            tags, e2 = escape_keys(tags)
            volatile = {path: escape_keys(value)[0] for path, value in volatile.items()}
            escaped = e1 or e2
        return {"rec": rec, "config": config, "tags": tags, "hash": digest, "key_escaped": escaped,
                "volatile": volatile}

    def _save_batch(self, scan_id: str, batch: list[ResourceRecord], now: datetime, coll) -> SaveStats:
        stats = SaveStats()
        prepared = {r.key: self._prepare(r) for r in batch}
        existing = {
            d["_id"]: d for d in coll.find(
                {"_id": {"$in": list(prepared)}}, {"config_hash": 1, "config_chunks": 1})
        }
        changed_old = [k for k, p in prepared.items() if k in existing and existing[k]["config_hash"] != p["hash"]]
        old_full = {d["_id"]: d for d in coll.find({"_id": {"$in": changed_old}})} if changed_old else {}

        ops, history, chunk_ops = [], [], []
        for key, p in prepared.items():
            rec: ResourceRecord = p["rec"]
            old = existing.get(key)
            if old is not None and old["config_hash"] == p["hash"]:
                touched = {"scan_id": scan_id, "last_seen": now}
                if "detail_checked_at" in rec.extra:  # when the details were last read in full (see spec ``change_marker``)
                    touched["detail_checked_at"] = rec.extra["detail_checked_at"]
                if not old.get("config_chunks"):  # keep "last used" style fields current, without a history entry
                    touched.update({f"config.{path}": value for path, value in p["volatile"].items()})
                ops.append(UpdateOne({"_id": key}, {"$set": touched, "$unset": {"deleted_at": ""}}))
                stats.unchanged += 1
                continue

            if old is None:
                stats.inserted += 1
            else:
                stats.updated += 1
                history.append(self._history_doc(old_full[key], scan_id, now))

            fields = {
                "account_id": rec.account_id, "region": rec.region, "service": rec.service,
                "resource_type": rec.resource_type, "resource_id": rec.resource_id, "arn": rec.arn,
                "tags": p["tags"], "config_hash": p["hash"], "key_escaped": p["key_escaped"],
                "scan_id": scan_id, "last_seen": now, "config_changed_at": now, **rec.extra,
            }
            size = len(json.dumps(p["config"], ensure_ascii=False))
            if size > self.cfg.max_doc_bytes:
                fields["config"], fields["config_chunks"] = None, self._chunk(key, p, chunk_ops)
                stats.chunked += 1
            else:
                fields["config"], fields["config_chunks"] = p["config"], 0
            if old is not None and old.get("config_chunks") and not fields["config_chunks"]:
                chunk_ops.append(("delete", key, None))
            ops.append(UpdateOne({"_id": key}, {"$set": fields, "$unset": {"deleted_at": ""},
                                                "$setOnInsert": {"first_seen": now}}, upsert=True))

        self._apply_chunk_ops(chunk_ops)
        if history:
            self.coll("resource_history").insert_many(history, ordered=False)
            stats.history = len(history)
        if ops:
            coll.bulk_write(ops, ordered=False)
        return stats

    def _chunk(self, key: str, p: dict, chunk_ops: list) -> int:
        text = json.dumps(p["config"], ensure_ascii=False)
        step = max(1000, self.cfg.chunk_bytes // 4)  # <=4 bytes per char keeps every chunk under chunk_bytes
        parts = [text[i:i + step] for i in range(0, len(text), step)]
        for idx, part in enumerate(parts):
            chunk_ops.append(("put", key, {"_id": f"{key}:{idx}", "resource_id": key, "idx": idx,
                                           "config_hash": p["hash"], "text": part}))
        return len(parts)

    def _apply_chunk_ops(self, chunk_ops: list) -> None:
        puts = [op[2] for op in chunk_ops if op[0] == "put"]
        for _, key, _ in (op for op in chunk_ops if op[0] == "delete"):  # no longer chunked
            self.coll("resource_chunks").delete_many({"resource_id": key})
        for key, digest in {op[1]: op[2]["config_hash"] for op in chunk_ops if op[0] == "put"}.items():
            self.coll("resource_chunks").delete_many({"resource_id": key, "config_hash": {"$ne": digest}})  # stale parts
        if puts:
            self.coll("resource_chunks").bulk_write([ReplaceOne({"_id": c["_id"]}, c, upsert=True) for c in puts], ordered=False)

    def _history_doc(self, old: dict, scan_id: str, now: datetime) -> dict:
        chunked = bool(old.get("config_chunks"))
        return {
            "resource_key": old["_id"], "account_id": old.get("account_id"), "region": old.get("region"),
            "service": old.get("service"), "resource_type": old.get("resource_type"),
            "resource_id": old.get("resource_id"),
            "config": None if chunked else old.get("config"), "tags": old.get("tags"),
            "config_hash": old.get("config_hash"), "key_escaped": old.get("key_escaped", False),
            "config_truncated": chunked,  # oversized configs are not copied into history
            "version_scan_id": old.get("scan_id"), "changed_at": now, "changed_in_scan": scan_id,
        }

    def get_config(self, doc: dict):
        """Rebuild the original config of a ``resources`` document (reassemble chunks, unescape keys)."""
        config = doc.get("config")
        if doc.get("config_chunks"):
            parts = sorted(self.coll("resource_chunks").find({"resource_id": doc["_id"]}), key=lambda c: c["idx"])
            config = json.loads("".join(c["text"] for c in parts))
        return unescape_keys(config) if doc.get("key_escaped") else config

    def previous_details(self, account_id: str, region: str, service: str, resource_type: str) -> dict[str, dict]:
        """The stored copies of one task's resources of a type, for the "details unchanged" shortcut: resource id ->
        ``{"config", "detail_checked_at"}``. Deleted and chunked (oversized) copies are left out: those are read in full."""
        found = {}
        for d in self.coll("resources").find({"account_id": account_id, "region": region, "service": service,
                                              "resource_type": resource_type, "deleted_at": None,
                                              "config_chunks": {"$in": [0, None]}},
                                             {"resource_id": 1, "config": 1, "key_escaped": 1, "config_chunks": 1, "detail_checked_at": 1}):
            found[d["resource_id"]] = {"config": self.get_config(d), "detail_checked_at": d.get("detail_checked_at")}
        return found

    # ------------------------------------------------------------------ status / settings
    def record_status(self, scan_id: str, rows: Iterable[StatusRecord]) -> int:
        now = now_utc()
        docs = [{
            "scan_id": scan_id, "account_id": r.account_id, "region": r.region, "service": r.service,
            "api": r.api, "resource_type": r.resource_type, "status": r.status.value,
            "error_code": r.error_code, "error": r.error, "resource_count": r.resource_count,
            "duration_ms": round(r.duration_ms, 1), "api_calls": r.api_calls,
            "affects_sweep": r.affects_sweep, "created_at": now,
        } for r in rows]
        if docs:
            self.coll("collection_status").insert_many(docs, ordered=False)
        return len(docs)

    def save_account_setting(self, scan_id: str, account_id: str, region: str, setting: str, value) -> None:
        value = normalize(value)
        escaped = False
        if self.cfg.escape_keys:
            value, escaped = escape_keys(value)
        key = {"scan_id": scan_id, "account_id": account_id, "region": region, "setting": setting}
        self.coll("account_settings").update_one(
            key, {"$set": {"value": value, "key_escaped": escaped, "collected_at": now_utc()}}, upsert=True)

    # ------------------------------------------------------------------ soft delete
    def sweep(self, scan_id: str, scopes: Iterable[SweepScope], now: datetime | None = None,
              collection: str = "resources") -> int:
        """Mark resources not seen in this scan as deleted, only inside fully collected scopes."""
        now = now or now_utc()
        deleted = 0
        for s in scopes:
            flt = {"account_id": s.account_id, "region": s.region, "service": s.service,
                   "scan_id": {"$ne": scan_id}, "deleted_at": None}
            if s.resource_types is not None:
                flt["resource_type"] = {"$in": sorted(s.resource_types)}
            deleted += self.coll(collection).update_many(flt, {"$set": {"deleted_at": now}}).modified_count
        return deleted


def rename_collections(db: Database, from_prefix: str, to_prefix: str) -> list[tuple[str, str]]:
    """Rename this collector's collections from one prefix to another (data and indexes are kept).

    Safe by construction: only the collector's own names are touched, the source set must be recognisably ours
    (its ``cspm_meta`` marker exists) and no target may exist yet, otherwise nothing is renamed.
    """
    if from_prefix == to_prefix:
        raise ValueError("from and to prefix are the same")
    existing = set(db.list_collection_names())
    if from_prefix + META not in existing:
        raise ValueError(f"'{from_prefix + META}' not found: these collections were not created by this collector")
    pairs = [(from_prefix + n, to_prefix + n) for n in (*MANAGED_COLLECTIONS, META) if from_prefix + n in existing]
    taken = sorted(new for _, new in pairs if new in existing)
    if taken:
        raise ValueError(f"target collections already exist: {taken}")
    for old, new in pairs:
        db[old].rename(new)
    return pairs
