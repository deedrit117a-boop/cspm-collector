"""The action list, the relation-index status, the Akamai summary and the batch mark on runs."""
from datetime import datetime, timedelta

import mongomock

from cspm_collector.core.config import MongoSettings
from cspm_collector.storage.records import Status, StatusRecord
from cspm_collector.storage.store import Store
from cspm_collector.web.actions import akamai_summary, edges_status, needs_action
from test_health import scan, T0

NAMES = {"A": "alpha", "B": "beta", "C": "gamma"}


def store_():
    s = Store(mongomock.MongoClient()["d"], MongoSettings())
    s.init_db()
    return s


def acct_failure(store, scan_id, account, code, error):
    store.record_status(scan_id, [StatusRecord(account, "*", "*", "*", Status.ERROR, error_code=code, error=error, affects_sweep=False)])


def test_an_account_left_out_of_the_newest_run_is_listed_with_the_fix_and_disappears_when_a_later_run_includes_it():
    s = store_()
    first = scan(s, 1, {"A": {}})
    acct_failure(s, first, "B", "SSO_LOGIN_NEEDED", "로그인이 필요합니다")
    got = needs_action(s, NAMES)
    assert [(r["account_id"], r["code"]) for r in got["accounts"]] == [("B", "SSO_LOGIN_NEEDED")]
    assert "aws sso login" in got["accounts"][0]["fix"] and got["count"] == 1
    scan(s, 2, {"A": {}, "B": {"resources": 3}})  # B went through in a newer run
    assert needs_action(s, NAMES)["accounts"] == []


def test_a_failed_connection_check_counts_unless_a_newer_run_went_through():
    s = store_()
    scan(s, 1, {"A": {}})
    s.coll("runtime").update_one({"_id": "account_checks"}, {"$set": {"results": {
        "A": {"ok": False, "code": "ASSUME_DENIED", "label": "Role 거부", "message": "denied", "hint": "check trust", "at": T0 + timedelta(days=2)},
        "C": {"ok": True, "at": T0 + timedelta(days=2)},
        "ZZ": {"ok": False, "code": "X", "at": T0 + timedelta(days=2)}}}}, upsert=True)  # ZZ is not a configured account
    got = needs_action(s, NAMES)["accounts"]
    assert [(r["account_id"], r["source"], r["label"]) for r in got] == [("A", "check", "Role 거부")]
    scan(s, 3, {"A": {}})  # newer than the check: the check is outdated
    assert needs_action(s, NAMES)["accounts"] == []


def test_denied_calls_are_grouped_per_account_and_item_for_the_newest_run_only():
    s = store_()
    old = scan(s, 1, {"A": {}})
    s.record_status(old, [StatusRecord("A", "ap-northeast-2", "sqs", "list_queues", Status.ACCESS_DENIED, error="old")])
    new = scan(s, 2, {"A": {}})
    s.record_status(new, [StatusRecord("A", r, "wafv2", api, Status.ACCESS_DENIED, error="not authorized")
                          for r in ("us-east-1", "ap-northeast-2") for api in ("list_ip_sets", "get_ip_set")] +
                    [StatusRecord("A", "ap-northeast-2", "ec2", "describe_vpcs", Status.SUCCESS)])
    d = needs_action(s, NAMES)
    assert [(e["account_id"], e["service"], e["count"]) for e in d["denied"]] == [("A", "wafv2", 4)]
    assert d["denied"][0]["apis"] == ["list_ip_sets", "get_ip_set"] and d["denied_total"] == 1


def edge(i, rel="uses_security_group", dst_type="security_group", dst_key="k", last_seen=T0, deleted_at=None):
    return {"_id": str(i), "rel": rel, "dst_type": dst_type, "dst_key": dst_key, "last_seen": last_seen, "deleted_at": deleted_at}


def test_edges_status_counts_live_relations_dangling_targets_and_age():
    s = store_()
    assert edges_status(s, T0)["total"] == 0
    s.coll("edges").insert_many([edge(1), edge(2, dst_key=None), edge(3, rel="has_hostname", dst_type="hostname", dst_key=None),
                                 edge(4, last_seen=T0 + timedelta(days=2)), edge(5, deleted_at=T0)])
    got = edges_status(s, T0 + timedelta(days=5))
    assert got["total"] == 4 and got["deleted"] == 1 and got["dangling"] == 1  # the hostname node has no document by design
    assert {r["rel"]: r["count"] for r in got["rels"]} == {"uses_security_group": 3, "has_hostname": 1}
    assert got["newest"] == T0 + timedelta(days=2) and got["stale_days"] == 3.0


def test_akamai_summary_lists_kinds_and_what_the_contract_cannot_give():
    s = store_()
    base = {"account_id": "x", "service": "akamai"}
    s.coll("akamai_raw").insert_many([{**base, "region": "global", "resource_id": rid, "resource_type": rt, "last_seen": seen, "deleted_at": gone}
                                      for rid, rt, seen, gone in (("1", "appsec_ip_geo_firewall", T0, None), ("2", "appsec_ip_geo_firewall", T0 + timedelta(days=1), None),
                                                                  ("3", "network_list", T0, None), ("4", "gone", T0, T0))])
    s.record_status("s1", [StatusRecord("x", "global", "akamai", "appsec_bypass_network_lists", Status.NOT_SUPPORTED)])
    got = akamai_summary(s)
    assert {k["resource_type"]: k["count"] for k in got["kinds"]} == {"appsec_ip_geo_firewall": 2, "network_list": 1}
    assert got["not_supported"] == ["appsec_bypass_network_lists"]


def test_the_new_endpoints_answer_on_an_empty_database():
    from test_web_api import make

    client, rt, _, store = make()
    try:
        for url in ("/api/health/actions", "/api/health/edges", "/api/akamai/summary"):
            assert client.get(url).status_code == 200
        assert client.get("/api/health/edges").json()["total"] == 0
    finally:
        rt.stop()
