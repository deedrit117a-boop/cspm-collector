"""What a person has to do now, and two small status views (the relation index, the Akamai data).

* ``needs_action``: accounts that cannot be collected as things stand. From two sources, newest wins per account: the connection
  check of the accounts page (``runtime.account_checks``) and the account-level failure row (``region="*"``, ``service="*"``)
  of the newest finished run that included the account. An account that was fine in a newer run is not listed. The second
  list is "permission denied" per account and item in that newest run (the usual sign of an IAM policy that is not applied).
* ``edges_status``: size and age of the relation index (``edges``), and the share of relations whose target is not stored.
* ``akamai_summary``: how many documents of each Akamai kind are stored, and which kinds this contract cannot give.
"""
from __future__ import annotations

from datetime import datetime

from cspm_collector.storage.store import Store

from .checks import LABELS

MAX_DENIED = 60
VIRTUAL_TARGETS = ("hostname", "ip")  # these have no stored document, so a missing dst_key is normal

# what to do for the codes of the pre-run check and the account opening (the message of the row has the details)
FIX = {
    "SSO_LOGIN_NEEDED": "터미널에서 `aws sso login --profile <프로필>`을 실행하세요.",
    "ASSUME_DENIED": "수집 Role의 신뢰 정책과 서버 자격증명의 sts:AssumeRole 권한을 확인하세요.",
    "EXTERNAL_ID_ENV_MISSING": "Role이 요구하는 External ID 환경변수를 서버를 시작한 셸에 설정하세요.",
    "PROFILE_MISSING": "`~/.aws/config`에 이 프로필이 있는지, 어카운트 설정의 프로필 이름이 같은지 확인하세요.",
    "CREDENTIALS_EXPIRED": "서버가 쓰는 자격증명을 새로 받으세요(SSO라면 `aws sso login`).",
    "NETWORK": "서버에서 AWS(STS) 엔드포인트로 나갈 수 있는지, 프록시와 사내 CA 번들 설정을 확인하세요.",
    "ACCOUNT_MISMATCH": "어카운트 ID와 프로필·Role이 같은 어카운트를 가리키는지 확인하세요.",
    "PREFLIGHT_FAILED": "어카운트 화면에서 이 어카운트의 연결 확인 결과를 열어 보세요.",
}


def _row(account_id: str, names: dict[str, str], source: str, code: str, label: str | None, message: str, at, scan_id: str | None = None) -> dict:
    return {"account_id": account_id, "name": names.get(account_id, account_id), "source": source, "code": code, "label": label or LABELS.get(code, code),
            "message": message, "fix": FIX.get(code), "at": at, "scan_id": scan_id}


def needs_action(store: Store, names: dict[str, str]) -> dict:
    newest: dict[str, tuple] = {}  # account -> (started_at, scan_id) of the newest finished, not cancelled run that included it
    scans = {s["scan_id"]: s for s in store.coll("scans").find({"status": {"$nin": ["RUNNING", "CANCELLED"]}}, {"scan_id": 1, "started_at": 1})
             .sort("started_at", -1).limit(40) if s.get("started_at")}
    for d in store.coll("scan_accounts").find({"scan_id": {"$in": list(scans)}}, {"scan_id": 1, "account_id": 1, "status": 1}):
        at = scans[d["scan_id"]]["started_at"]
        if d["account_id"] not in newest or at > newest[d["account_id"]][0]:
            newest[d["account_id"]] = (at, d["scan_id"], d.get("status"))
    # accounts that were left out before opening have no scan_accounts row: they only have the account-level failure row
    last_failed: dict[str, dict] = {}
    for r in store.coll("collection_status").find({"scan_id": {"$in": list(scans)}, "region": "*", "service": "*"}):
        at = scans[r["scan_id"]]["started_at"]
        if r["account_id"] not in last_failed or at > last_failed[r["account_id"]]["_at"]:
            last_failed[r["account_id"]] = {**r, "_at": at}
    last_failed = {a: r for a, r in last_failed.items() if a in names}  # an account that is no longer configured needs nothing
    for acct, r in last_failed.items():  # a failed account has no result row, so the failure itself counts as its newest run
        if acct not in newest or r["_at"] > newest[acct][0]:
            newest[acct] = (r["_at"], r["scan_id"], "FAILED")

    rows: dict[str, dict] = {}
    for acct, r in last_failed.items():
        if r["scan_id"] == newest[acct][1]:
            rows[acct] = _row(acct, names, "run", r.get("error_code") or "ERROR", None, r.get("error") or "", r["_at"], r["scan_id"])
    checks = ((store.coll("runtime").find_one({"_id": "account_checks"}) or {}).get("results")) or {}
    for acct, c in checks.items():
        if c.get("ok") or acct not in names or not c.get("at"):
            continue
        if acct in rows and rows[acct]["at"] >= c["at"]:
            continue
        # a check older than a run that went through is outdated
        if acct in newest and newest[acct][2] not in (None, "FAILED") and newest[acct][0] > c["at"]:
            continue
        rows[acct] = _row(acct, names, "check", c.get("code") or "ERROR", c.get("label"),
                          f"{c.get('message', '')} {c.get('hint', '')}".strip(), c["at"])

    denied: dict[tuple, dict] = {}
    for acct, (_at, scan_id, _st) in newest.items():
        for r in store.coll("collection_status").find({"scan_id": scan_id, "account_id": acct, "status": "ACCESS_DENIED"},
                                                      {"service": 1, "api": 1, "error": 1}).limit(2000):
            e = denied.setdefault((acct, r["service"]), {"account_id": acct, "name": names.get(acct, acct), "service": r["service"],
                                                         "count": 0, "apis": [], "sample": (r.get("error") or "")[:300], "scan_id": scan_id})
            e["count"] += 1
            if r.get("api") and r["api"] not in e["apis"] and len(e["apis"]) < 6:
                e["apis"].append(r["api"])
    denied_rows = sorted(denied.values(), key=lambda e: (-e["count"], e["name"].lower(), e["service"]))
    return {"accounts": sorted(rows.values(), key=lambda r: (r["code"], r["name"].lower())), "denied": denied_rows[:MAX_DENIED],
            "denied_total": len(denied_rows), "count": len(rows) + len(denied_rows)}


def edges_status(store: Store, now: datetime) -> dict:
    coll = store.coll("edges")
    live = {"deleted_at": None}
    total = coll.count_documents(live)
    if not total:
        return {"total": 0, "deleted": coll.count_documents({"deleted_at": {"$ne": None}}), "newest": None, "oldest": None, "rels": [], "dangling": 0}
    rels = [{"rel": r["_id"], "count": r["n"]} for r in coll.aggregate(
        [{"$match": live}, {"$group": {"_id": "$rel", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}])]
    newest = coll.find(live, {"last_seen": 1}).sort("last_seen", -1).limit(1)[0].get("last_seen")
    oldest = coll.find(live, {"last_seen": 1}).sort("last_seen", 1).limit(1)[0].get("last_seen")
    dangling = coll.count_documents({**live, "dst_key": None, "dst_type": {"$nin": list(VIRTUAL_TARGETS)}})
    return {"total": total, "deleted": coll.count_documents({"deleted_at": {"$ne": None}}), "newest": newest, "oldest": oldest,
            "rels": rels[:40], "dangling": dangling, "stale_days": None if newest is None else round((now - newest).total_seconds() / 86400, 1)}


def akamai_summary(store: Store) -> dict:
    coll = store.coll("akamai_raw")
    kinds = [{"resource_type": r["_id"], "count": r["n"], "newest": r["newest"]} for r in coll.aggregate(
        [{"$match": {"deleted_at": None}}, {"$group": {"_id": "$resource_type", "n": {"$sum": 1}, "newest": {"$max": "$last_seen"}}}, {"$sort": {"_id": 1}}])]
    unsupported = sorted({r.get("api") or r.get("resource_type") or "?" for r in store.coll("collection_status").find(
        {"service": "akamai", "status": "NOT_SUPPORTED"}, {"api": 1, "resource_type": 1}).sort("created_at", -1).limit(200)})
    return {"kinds": kinds, "not_supported": unsupported}
