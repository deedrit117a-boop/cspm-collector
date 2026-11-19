"""Collection health: per-account history of the last runs and the warnings drawn from it."""
from datetime import datetime, timedelta

import mongomock

from cspm_collector.core.config import MongoSettings
from cspm_collector.storage.store import Store
from cspm_collector.web.health import collection_health
from test_web_api import make

T0 = datetime(2026, 10, 1, 3, 0)


def store_():
    s = Store(mongomock.MongoClient()["d"], MongoSettings())
    s.init_db()
    return s


def scan(store, n, accounts, status="COMPLETED", trigger="schedule"):
    """Scan number ``n`` (older = smaller); ``accounts``: {id: {status, resources, seconds, tasks, services}}."""
    sid = f"s{n:02d}"
    store.create_scan(sid, list(accounts), "v", None, {"trigger": {"type": trigger}})
    store.finish_scan(sid, status, {})
    store.coll("scans").update_one({"scan_id": sid}, {"$set": {"started_at": T0 + timedelta(days=n)}})
    store.save_scan_accounts(sid, {a: {"status": "COMPLETED", "resources": 0, "seconds": 5.0, "tasks": 3, "services": {}, **v}
                                   for a, v in accounts.items()})
    return sid


def health(store, **kw):
    return collection_health(store, {"A": "alpha", "B": "beta"}, **kw)


def warns(h, account):
    return {w["type"]: w for a in h["accounts"] if a["account_id"] == account for w in a["warnings"]}


def test_columns_follow_the_runs_and_each_account_gets_its_rate_and_average():
    store = store_()
    scan(store, 1, {"A": {"seconds": 10.0}})
    scan(store, 2, {"A": {"status": "FAILED", "seconds": 20.0, "error": "SSOTokenLoadError: expired"}, "B": {"seconds": 6.0}}, status="PARTIAL")
    h = health(store)
    assert [s["scan_id"] for s in h["scans"]] == ["s02", "s01"]  # newest first
    a = next(x for x in h["accounts"] if x["account_id"] == "A")
    assert [r["status"] if r else None for r in a["runs"]] == ["FAILED", "COMPLETED"]
    assert a["success_rate"] == 0.5 and a["avg_seconds"] == 15.0 and a["name"] == "alpha"
    b = next(x for x in h["accounts"] if x["account_id"] == "B")
    assert b["runs"][1] is None and b["success_rate"] == 1.0  # B was not in the older run


def test_two_runs_in_a_row_that_did_not_complete_are_a_warning_but_a_cancelled_run_is_ignored():
    store = store_()
    scan(store, 1, {"A": {}})
    scan(store, 2, {"A": {"status": "FAILED", "error": "boom"}}, status="PARTIAL")
    scan(store, 3, {"A": {"status": "FAILED", "tasks": 0}}, status="CANCELLED")
    assert "failing" not in warns(health(store), "A")  # only one real failure so far (the cancelled run does not count)
    scan(store, 4, {"A": {"status": "PARTIAL"}}, status="PARTIAL")
    w = warns(health(store), "A")
    assert "failing" in w and health(store)["warning_count"] == 1


def test_a_big_drop_of_an_items_resources_is_reported_when_both_runs_completed():
    store = store_()
    scan(store, 1, {"A": {"services": {"sqs": {"resources": 40}, "sns": {"resources": 3}}}})
    scan(store, 2, {"A": {"services": {"sqs": {"resources": 12}, "sns": {"resources": 0}}}})
    w = warns(health(store), "A")
    assert w["drop"]["service"] == "sqs" and (w["drop"]["before"], w["drop"]["now"]) == (40, 12)  # sns: too few before to judge
    assert len([x for x in health(store)["accounts"][0]["warnings"] if x["type"] == "drop"]) == 1


def test_no_drop_warning_after_a_retry_a_cancelled_run_or_a_partial_run():
    for status, trigger, acct_status in (("COMPLETED", "retry", "COMPLETED"), ("CANCELLED", "schedule", "COMPLETED"),
                                         ("PARTIAL", "schedule", "PARTIAL")):
        store = store_()
        scan(store, 1, {"A": {"services": {"sqs": {"resources": 40}}}})
        scan(store, 2, {"A": {"status": acct_status, "services": {"sqs": {"resources": 1}}}}, status=status, trigger=trigger)
        assert "drop" not in warns(health(store), "A"), (status, trigger)


def test_a_run_much_slower_than_usual_is_reported_only_with_enough_history_and_real_time():
    store = store_()
    for n in range(1, 5):
        scan(store, n, {"A": {"seconds": 40.0}})
    scan(store, 5, {"A": {"seconds": 130.0}})
    w = warns(health(store), "A")
    assert "slow" in w and "3.2배" in w["slow"]["message"]
    quick = store_()
    for n in range(1, 5):
        quick_ = scan(quick, n, {"A": {"seconds": 2.0}})
    scan(quick, 5, {"A": {"seconds": 9.0}})
    assert "slow" not in warns(health(quick), "A")  # 4.5x, but a few seconds: not news
    young = store_()
    scan(young, 1, {"A": {"seconds": 40.0}})
    scan(young, 2, {"A": {"seconds": 400.0}})
    assert "slow" not in warns(health(young), "A")  # no usual time to compare with yet


def test_endpoint_uses_the_account_names_and_clamps_the_limit():
    client, rt, stub, store = make(akamai=True)
    try:
        scan(store, 1, {"111": {"seconds": 5.0}, "akamai:main": {"seconds": 9.0}})
        h = client.get("/api/health/collection?limit=1000").json()
        assert {a["account_id"]: a["name"] for a in h["accounts"]} == {"111": "dev", "akamai:main": "main (Akamai)"}
        assert len(h["scans"]) == 1
    finally:
        rt.stop()


# ----------------------------------------------------------------------------- data freshness
from cspm_collector.web.health import freshness  # noqa: E402

NOW = T0 + timedelta(days=21)


def svc(failed=0, tasks=3):
    return {"tasks": tasks, "resources": 5, "seconds": 1.0, "failed": failed}


def test_an_item_that_keeps_failing_inside_completed_runs_gets_listed_as_stale():
    store = store_()
    scan(store, 10, {"A": {"services": {"sqs": svc(), "sns": svc(), "kms": svc(failed=2)}}})
    for n in (14, 17, 20):  # sqs fine every time, sns and kms fail from here on although the run "completed"
        scan(store, n, {"A": {"services": {"sqs": svc(), "sns": svc(failed=1), "kms": svc(failed=3)}}})
    f = freshness(store, {"A": "alpha"}, days=7, now=NOW)
    a = f["accounts"][0]
    assert (a["name"], a["items"], a["stale_count"]) == ("alpha", 3, 2)
    assert [(x["service"], x["last_success"], x["age_days"]) for x in a["stale"]] == [
        ("kms", None, None),  # never succeeded: first
        ("sns", T0 + timedelta(days=10), 11.0)]
    assert a["newest"] == T0 + timedelta(days=20)  # sqs
    assert f["stale_accounts"] == 1 and {s["service"]: s["accounts"] for s in f["services"]} == {"kms": 1, "sns": 1}
    wide = freshness(store, {"A": "alpha"}, days=14, now=NOW)["accounts"][0]
    assert [x["service"] for x in wide["stale"]] == ["kms"]  # sns succeeded 11 days ago: fine for a 14-day limit


def test_fresh_accounts_and_items_that_were_never_collected_are_not_stale():
    store = store_()
    scan(store, 20, {"A": {"services": {"sqs": svc()}}, "B": {"services": {"sqs": svc(), "s3": svc(tasks=0)}}})
    f = freshness(store, {}, days=7, now=NOW)
    assert f["stale_accounts"] == 0 and [a["stale_count"] for a in f["accounts"]] == [0, 0]
    assert next(a for a in f["accounts"] if a["account_id"] == "B")["items"] == 1  # s3 ran no task: not an item of B


def test_runs_from_before_the_failure_counts_only_count_when_the_whole_account_completed():
    store = store_()
    old_ok = {"sqs": {"tasks": 3, "resources": 5, "seconds": 1.0}}  # no "failed" key
    scan(store, 19, {"A": {"status": "COMPLETED", "services": old_ok}, "B": {"status": "PARTIAL", "services": old_ok}})
    f = {a["account_id"]: a for a in freshness(store, {}, days=7, now=NOW)["accounts"]}
    assert f["A"]["stale_count"] == 0 and f["B"]["stale_count"] == 1 and f["B"]["stale"][0]["last_success"] is None


def test_freshness_endpoint_names_the_accounts_and_clamps_the_days():
    client, rt, stub, store = make()
    try:
        scan(store, 1, {"111": {"services": {"sqs": svc()}}})
        r = client.get("/api/health/freshness?days=100000").json()
        assert r["days"] == 365 and r["accounts"][0]["name"] == "dev"
    finally:
        rt.stop()
