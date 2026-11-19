"""Collection health: how each account did over the last runs, and what looks wrong.

Built from the per-account results of the scans (``scan_accounts``), nothing else is stored. Warnings:

* ``failing``  the last two runs of the account did not complete
* ``slow``     the last run took more than twice the usual time
* ``drop``     an item returned far fewer resources than in the run before (permissions that changed return an empty
               answer without any error, so a drop is the only sign). Only complete runs are compared, a retry or a
               cancelled run never is.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from statistics import median

from cspm_collector.storage.store import Store

DROP_RATIO = 0.7  # at most 70% of before ...
DROP_MIN_BEFORE = 10  # ... and at least this many before: small numbers jump around
SLOW_FACTOR = 2.0
SLOW_MIN_SECONDS = 30  # a run of a few seconds twice as slow is not news
SLOW_MIN_HISTORY = 3


def _trigger(scan: dict) -> str:
    return ((scan.get("options") or {}).get("trigger") or {}).get("type") or "cli"


def collection_health(store: Store, names: dict[str, str], limit: int = 10) -> dict:
    limit = max(3, min(int(limit), 30))
    scans = list(store.coll("scans").find({"status": {"$nin": ["RUNNING"]}}, {"scan_id": 1, "status": 1, "started_at": 1, "options.trigger": 1})
                 .sort("started_at", -1).limit(limit * 6))
    by_id = {s["scan_id"]: s for s in scans}
    docs = list(store.coll("scan_accounts").find({"scan_id": {"$in": list(by_id)}},
                                                 {"scan_id": 1, "account_id": 1, "status": 1, "resources": 1, "seconds": 1,
                                                  "tasks": 1, "services": 1, "error": 1}))
    per_acct: dict[str, list[dict]] = {}
    for d in docs:
        scan = by_id[d["scan_id"]]
        per_acct.setdefault(d["account_id"], []).append({
            "scan_id": d["scan_id"], "started_at": scan.get("started_at"), "scan_status": scan["status"], "trigger": _trigger(scan),
            "status": d.get("status") or "COMPLETED", "resources": d.get("resources", 0), "seconds": d.get("seconds", 0.0),
            "tasks": d.get("tasks", 0), "services": d.get("services") or {}, "error": d.get("error")})
    columns = [s for s in scans if any(s["scan_id"] == e["scan_id"] for es in per_acct.values() for e in es)][:limit]
    col_ids = [c["scan_id"] for c in columns]

    accounts, warning_count = [], 0
    for acct, entries in per_acct.items():
        entries.sort(key=lambda e: e["started_at"] or 0, reverse=True)  # newest first
        shown = [e for e in entries if e["scan_id"] in col_ids]
        warnings: list[dict] = []
        real = [e for e in entries if e["scan_status"] != "CANCELLED"]
        if len(real) >= 2 and all(e["status"] != "COMPLETED" for e in real[:2]):
            warnings.append({"type": "failing", "message": f"최근 {2}번 연속 완료하지 못했습니다" + (f": {real[0]['error']}" if real[0].get("error") else "")})
        times = [e["seconds"] for e in real[1:] if e["seconds"] and e["tasks"]]
        if real and len(times) >= SLOW_MIN_HISTORY and real[0]["tasks"]:
            usual = median(times)
            if real[0]["seconds"] >= max(SLOW_MIN_SECONDS, usual * SLOW_FACTOR):
                warnings.append({"type": "slow", "message": f"지난 수집이 평소({usual:.0f}초)의 {real[0]['seconds'] / usual:.1f}배인 {real[0]['seconds']:.0f}초 걸렸습니다"})
        complete = [e for e in entries if e["status"] == "COMPLETED" and e["scan_status"] in ("COMPLETED", "PARTIAL") and e["trigger"] != "retry"]
        latest_is_complete = bool(real) and bool(complete) and complete[0]["scan_id"] == real[0]["scan_id"]
        if latest_is_complete and len(complete) >= 2:
            now, before = complete[0]["services"], complete[1]["services"]
            for svc, cur in sorted(now.items()):
                prev = (before.get(svc) or {}).get("resources")
                if prev is not None and prev >= DROP_MIN_BEFORE and cur.get("resources", 0) <= prev * DROP_RATIO:
                    warnings.append({"type": "drop", "service": svc, "before": prev, "now": cur.get("resources", 0),
                                     "message": f"{svc}: {prev:,}건 → {cur.get('resources', 0):,}건으로 줄었습니다 (권한이 바뀌었는지 확인하세요)"})
        runs = {e["scan_id"]: e for e in shown}
        done = [e for e in shown if e["tasks"] or e["error"]]
        ok = sum(1 for e in done if e["status"] == "COMPLETED")
        warning_count += bool(warnings)
        accounts.append({
            "account_id": acct, "name": names.get(acct, acct),
            "runs": [({"scan_id": c, "status": runs[c]["status"], "resources": runs[c]["resources"], "seconds": runs[c]["seconds"],
                       "tasks": runs[c]["tasks"], "cancelled": runs[c]["scan_status"] == "CANCELLED"} if c in runs else None) for c in col_ids],
            "success_rate": round(ok / len(done), 2) if done else None,
            "avg_seconds": round(sum(e["seconds"] for e in done) / len(done), 1) if done else None,
            "warnings": warnings})
    accounts.sort(key=lambda a: (not a["warnings"], a["name"].lower()))
    return {"scans": [{"scan_id": c["scan_id"], "started_at": c.get("started_at"), "status": c["status"], "trigger": _trigger(c)} for c in columns],
            "accounts": accounts, "warning_count": warning_count}


STALE_DAYS = 7


def freshness(store: Store, names: dict[str, str], days: int = STALE_DAYS, scans_limit: int = 200, now: datetime | None = None) -> dict:
    """How old the data of each account and item is: the last run in which the item was read WITHOUT any failed API call.

    An item that keeps failing in a run that otherwise "completed" is invisible in the run's status; here its data simply
    gets older until it is listed as stale. Only items that were collected at some time within the recent runs are
    judged (what was never selected is not "stale"). Runs from before the per-item failure counts existed count as a
    success only when the whole account completed in them.
    """
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    days = max(1, min(int(days), 365))
    scans = {s["scan_id"]: s for s in store.coll("scans").find({"status": {"$nin": ["RUNNING"]}}, {"scan_id": 1, "started_at": 1})
             .sort("started_at", -1).limit(scans_limit)}
    seen: dict[str, dict[str, dict]] = {}  # account -> service -> {"ran": newest run it was tried, "ok": newest run without failures}
    for d in store.coll("scan_accounts").find({"scan_id": {"$in": list(scans)}}, {"scan_id": 1, "account_id": 1, "status": 1, "services": 1}):
        at = scans[d["scan_id"]].get("started_at")
        if at is None:
            continue
        for svc, st in (d.get("services") or {}).items():
            if not st.get("tasks"):
                continue
            ok = st["failed"] == 0 if "failed" in st else d.get("status") == "COMPLETED"
            e = seen.setdefault(d["account_id"], {}).setdefault(svc, {"ran": None, "ok": None})
            e["ran"] = max(filter(None, (e["ran"], at)))
            if ok:
                e["ok"] = max(filter(None, (e["ok"], at)))
    accounts, by_service = [], {}
    limit = now - timedelta(days=days)
    for acct, svcs in seen.items():
        stale = []
        for svc, e in svcs.items():
            if e["ok"] is None or e["ok"] < limit:
                stale.append({"service": svc, "last_success": e["ok"], "last_try": e["ran"],
                              "age_days": None if e["ok"] is None else round((now - e["ok"]).total_seconds() / 86400, 1)})
                by_service.setdefault(svc, []).append(e["ok"])
        stale.sort(key=lambda x: (x["last_success"] is not None, x["last_success"] or now))  # never succeeded first, then the oldest
        oks = [e["ok"] for e in svcs.values() if e["ok"]]
        accounts.append({"account_id": acct, "name": names.get(acct, acct), "items": len(svcs), "stale_count": len(stale),
                         "newest": max(oks) if oks else None, "oldest": min(oks) if oks else None, "stale": stale[:12]})
    accounts.sort(key=lambda a: (-a["stale_count"], a["name"].lower()))
    services = sorted(({"service": s, "accounts": len(v), "oldest": min((x for x in v if x), default=None)} for s, v in by_service.items()),
                      key=lambda x: -x["accounts"])
    return {"days": days, "accounts": accounts, "services": services[:30], "stale_accounts": sum(1 for a in accounts if a["stale_count"])}
