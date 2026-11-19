"""Used-region detection for many accounts at once (background batch, like the connection check).

Each account is probed with the free read-only calls of ``core/regions``; the latest result of every account is kept in
the database (``runtime`` document ``region_detect``), so the page shows it after a reload. Nothing is applied by the
detection itself: the user looks at the table and applies the regions of the accounts they choose.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable

from cspm_collector.core.config import AccountSettings
from cspm_collector.core.regions import Detection, UNKNOWN, USED
from cspm_collector.storage.store import Store

from .checks import classify

DETECT_ACCOUNT_WORKERS = 3  # each account already probes with a dozen threads


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def summarize(acct: AccountSettings, found: Detection) -> dict:
    """The stored result of one account: small (only used / unknown regions are listed)."""
    return {"account_id": acct.account_id, "name": acct.name, "ok": True, "current": acct.regions,
            "collect": found.collect, "used": found.by_state(USED), "unknown": found.by_state(UNKNOWN),
            "checked": len(found.regions), "seconds": found.seconds,
            "detail": [{"region": r.region, "state": r.state, "evidence": r.evidence}
                       for r in found.regions if r.state in (USED, UNKNOWN)],
            "at": _now()}


def drift(results: dict[str, dict], accounts: list[AccountSettings]) -> dict[str, dict]:
    """Regions that an account uses (found by the last detection) but has not listed: ``{account_id: {"name", "new": [...],
    "evidence": {region: [...]}, "checked_at"}}``. Only accounts with a fixed ``regions`` list can drift (an account with no
    list collects every enabled region anyway), and a failed detection never counts as a change."""
    out: dict[str, dict] = {}
    for a in accounts:
        r = results.get(a.account_id)
        if not a.regions or not r or not r.get("ok"):
            continue
        new = [x for x in r.get("used", []) if x not in a.regions]
        if new:
            evidence = {d["region"]: d.get("evidence", []) for d in r.get("detail", []) if d["region"] in new}
            out[a.account_id] = {"name": a.name, "new": new, "evidence": evidence, "checked_at": r.get("at")}
    return out


class RegionDetectRunner:
    def __init__(self, store: Store, load_accounts: Callable[[], list[AccountSettings]],
                 detect: Callable[[AccountSettings, tuple[str, ...]], Detection], workers: int = DETECT_ACCOUNT_WORKERS):
        self.store, self._load_accounts, self._detect, self.workers = store, load_accounts, detect, workers
        self._lock = threading.Lock()
        self._job: dict | None = None
        self._thread: threading.Thread | None = None

    def results(self) -> dict[str, dict]:
        doc = self.store.coll("runtime").find_one({"_id": "region_detect"})
        return dict((doc or {}).get("results") or {})

    def job(self) -> dict | None:
        with self._lock:
            return dict(self._job) if self._job else None

    def start(self, account_ids: list[str] | None, user: str) -> tuple[dict, bool]:
        with self._lock:
            if self._job and self._job["state"] == "running":
                return dict(self._job), False
            known = {a.account_id: a for a in self._load_accounts()}
            wanted = [known[i] for i in (account_ids if account_ids is not None else known) if i in known]
            self._job = {"state": "running", "total": len(wanted), "done": 0, "ok": 0, "failed": 0, "by": user,
                         "started_at": _now(), "finished_at": None}
            self._thread = threading.Thread(target=self._run, args=(wanted,), name="cspm-region-detect", daemon=True)
            self._thread.start()
            return dict(self._job), True

    def wait(self, timeout: float = 30.0) -> bool:  # for tests
        t = self._thread
        if t:
            t.join(timeout)
        return not (t and t.is_alive())

    def _run(self, accounts: list[AccountSettings]) -> None:
        coll = self.store.coll("runtime")

        def one(acct: AccountSettings) -> None:
            try:
                res = summarize(acct, self._detect(acct, tuple(acct.regions or ())))  # the regions set now stay pinned
            except Exception as exc:  # noqa: BLE001 - one account must neither stop the batch nor stay unreported
                code, message, hint = classify(exc, acct)
                res = {"account_id": acct.account_id, "name": acct.name, "ok": False, "current": acct.regions, "code": code,
                       "message": message, "hint": hint, "at": _now()}
            coll.update_one({"_id": "region_detect"}, {"$set": {f"results.{acct.account_id}": res}}, upsert=True)
            with self._lock:
                self._job["done"] += 1
                self._job["ok" if res["ok"] else "failed"] += 1

        try:
            with ThreadPoolExecutor(max_workers=max(1, min(self.workers, len(accounts) or 1))) as pool:
                list(pool.map(one, accounts))
        finally:
            with self._lock:
                self._job["state"] = "done"
                self._job["finished_at"] = _now()
