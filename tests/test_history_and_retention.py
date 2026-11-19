"""The change list (new / changed / deleted, with the differing fields) and the retention clean-up."""
from datetime import datetime, timedelta, timezone

import mongomock

from cspm_collector.core.config import MongoSettings
from cspm_collector.storage.records import ResourceRecord, SweepScope
from cspm_collector.storage.store import Store
from cspm_collector.web import retention
from cspm_collector.web.changes import change_detail, diff_values, recent_changes, resource_detail

T0 = datetime(2026, 10, 1, 3, 0)
NOW = T0 + timedelta(days=10)


def store_():
    s = Store(mongomock.MongoClient()["d"], MongoSettings())
    s.init_db()
    return s


def sg(i, **config):
    return ResourceRecord("111", "ap-northeast-2", "ec2", "security_group", i, config={"GroupId": i, **config}, arn=f"arn:{i}",
                          tags=[{"Key": "env", "Value": "dev"}])


# ----------------------------------------------------------------------------- diff
def test_diff_names_added_removed_and_changed_fields_and_ignores_the_order_of_plain_lists():
    old = {"a": 1, "b": {"c": [1, 2, 3]}, "gone": True}
    new = {"a": 2, "b": {"c": [3, 2, 4]}, "new": "x"}
    got = {(d["path"], d["kind"]): (d["before"], d["after"]) for d in diff_values(old, new)}
    assert got == {("a", "changed"): ("1", "2"), ("b.c", "removed"): ("1", None), ("b.c", "added"): (None, "4"),
                   ("gone", "removed"): ("True", None), ("new", "added"): (None, "x")}
    assert diff_values({"c": [1, 2]}, {"c": [2, 1]}) == []


# ----------------------------------------------------------------------------- the list
def test_changes_list_new_changed_and_deleted_and_the_first_collection_is_not_all_new():
    s = store_()
    s.save_resources("s1", [sg("a", Rules=[1]), sg("b")], now=T0)  # the first collection of the account: nothing is "new" yet
    s.save_resources("s2", [sg("a", Rules=[1, 2]), sg("b"), sg("c")], now=T0 + timedelta(days=3))
    s.sweep("s3", [SweepScope("111", "ap-northeast-2", "ec2", None)], now=T0 + timedelta(days=5))  # nothing seen in s3: all go
    events = recent_changes(s, NOW, days=30)
    kinds = sorted((e["kind"], e["resource_id"]) for e in events)
    assert kinds == [("changed", "a"), ("created", "c"), ("deleted", "a"), ("deleted", "b"), ("deleted", "c")]
    assert [e["kind"] for e in recent_changes(s, NOW, days=30, kinds=("changed",))] == ["changed"]
    assert [e["resource_id"] for e in recent_changes(s, NOW, days=30, text="C", kinds=("created",))] == ["c"]
    assert recent_changes(s, T0 + timedelta(days=40), days=7) == []  # nothing in the last week of that time


def test_detail_of_a_change_shows_only_what_differs_and_not_the_volatile_fields():
    s = store_()
    s.save_resources("s1", [sg("a", Rules=[1])], now=T0)
    s.save_resources("s2", [sg("a", Rules=[1, 2])], now=T0 + timedelta(days=1))
    (ev,) = recent_changes(s, NOW, days=30, kinds=("changed",))
    detail = change_detail(s, ev["id"])
    assert [(d["path"], d["kind"]) for d in detail["diff"]] == [("config.Rules", "added")]
    assert detail["diff"][0]["after"] == "2" and detail["previous_scan"] == "s1" and detail["scan_id"] == "s2"
    assert change_detail(s, "h:not-an-id") is None and change_detail(s, "r:missing") is None and change_detail(s, "x") is None


def test_each_change_is_compared_with_the_next_version_not_always_with_the_latest():
    s = store_()
    for n, rules in enumerate(([1], [1, 2], [1, 2, 3])):
        s.save_resources(f"s{n}", [sg("a", Rules=rules)], now=T0 + timedelta(days=n))
    oldest = sorted(recent_changes(s, NOW, days=30, kinds=("changed",)), key=lambda e: e["at"])[0]
    assert [(d["kind"], d["after"]) for d in change_detail(s, oldest["id"])["diff"]] == [("added", "2")]  # [1] -> [1, 2]


def test_resource_detail_has_the_config_as_text_the_tags_and_the_times_it_changed():
    s = store_()
    s.save_resources("s1", [sg("a", Rules=[1])], now=T0)
    s.save_resources("s2", [sg("a", Rules=[1, 2])], now=T0 + timedelta(days=1))
    (ev,) = recent_changes(s, NOW, days=30, kinds=("changed",))
    assert ev["key"]  # an event carries the key of its resource
    got = resource_detail(s, ev["key"])
    assert got["resource_id"] == "a" and '"Rules"' in got["config_text"] and got["config_cut"] is False
    assert [h["id"] for h in got["history"]] == [ev["id"]] and got["tags"][0]["key"] == "env"
    assert resource_detail(s, "missing") is None


# ----------------------------------------------------------------------------- retention
def seed(s):
    for n in range(30):  # 30 finished scans, a day apart, the newest 20 are always kept
        s.create_scan(f"s{n:02d}", ["111"], "v")
        s.finish_scan(f"s{n:02d}", "COMPLETED", {})
        s.coll("scans").update_one({"scan_id": f"s{n:02d}"}, {"$set": {"started_at": T0 + timedelta(days=n)}})
        s.record_status(f"s{n:02d}", [])
    s.save_resources("s00", [sg("live"), sg("old-gone"), sg("recent-gone")], now=T0)
    s.save_resources("s01", [sg("live", Rules=[1])], now=T0 + timedelta(days=1))  # a history entry from day 1
    s.coll("resources").update_one({"resource_id": "old-gone"}, {"$set": {"deleted_at": T0}})
    s.coll("resources").update_one({"resource_id": "recent-gone"}, {"$set": {"deleted_at": T0 + timedelta(days=15)}})
    s.coll("audit").insert_many([{"at": T0, "user": "x", "action": "a", "detail": {}}, {"at": T0 + timedelta(days=16), "user": "x", "action": "b", "detail": {}}])


def test_preview_counts_without_deleting_and_purge_keeps_what_is_current():
    s = store_()
    seed(s)
    cfg = retention.RetentionSettings(enabled=True, scans_days=7, history_days=7, deleted_days=7, audit_days=7)
    later = T0 + timedelta(days=17)  # the cutoff of every 7-day period is day 10
    pv = retention.preview(s, cfg, later)
    assert pv["scans"]["remove"] == 10 and pv["history"]["remove"] == 1 and pv["deleted"]["remove"] == 1 and pv["audit"]["remove"] == 1
    assert s.coll("scans").count_documents({}) == 30  # preview deleted nothing
    removed = retention.purge(s, cfg, later)
    assert removed["scans"] == 10 and removed["resource_history"] == 1 and removed["resources"] == 1 and removed["audit"] == 1
    left = {d["resource_id"] for d in s.coll("resources").find({})}
    assert left == {"live", "recent-gone"}  # a resource that is still seen is never touched; one deleted two days ago stays
    assert sorted(d["scan_id"] for d in s.coll("scans").find({}))[0] == "s10"  # the newest 20 are kept


def test_the_newest_scans_are_kept_even_when_they_are_all_older_than_the_period():
    s = store_()
    seed(s)
    retention.purge(s, retention.RetentionSettings(enabled=True, scans_days=7), NOW + timedelta(days=400))
    assert s.coll("scans").count_documents({}) == retention.KEEP_SCANS


def test_a_period_left_empty_keeps_that_kind_of_data_forever():
    s = store_()
    seed(s)
    cfg = retention.RetentionSettings(enabled=True, scans_days=None, history_days=None, deleted_days=None, audit_days=None)
    assert retention.purge(s, cfg, NOW + timedelta(days=4000)) == {}


# ----------------------------------------------------------------------------- over HTTP
def test_endpoints_for_changes_and_retention():
    from test_web_api import UI, make

    client, rt, _, store = make()
    try:
        store.save_resources("s1", [sg("a", Rules=[1])], now=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2))
        store.save_resources("s2", [sg("a", Rules=[1, 2])], now=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1))
        ev = client.get("/api/changes?days=7&kinds=changed").json()["events"]
        assert [e["resource_id"] for e in ev] == ["a"] and ev[0]["account"]
        detail = client.get("/api/changes/detail", params={"id": ev[0]["id"]}).json()
        assert detail["diff"][0]["path"] == "config.Rules"
        assert client.get("/api/changes/detail", params={"id": "h:zzz"}).status_code == 404
        assert client.get("/api/resources/detail", params={"key": ev[0]["key"]}).json()["resource_id"] == "a"
        assert client.get("/api/resources/detail", params={"key": "nope"}).status_code == 404

        got = client.get("/api/settings/retention").json()
        assert got["enabled"] is False and got["scans_days"] == 90 and got["limits"] == [7, 3650]
        assert client.put("/api/settings/retention", json={**{k: got[k] for k in ("enabled", "scans_days", "history_days", "deleted_days", "audit_days")},
                                                           "scans_days": 3}, headers=UI).status_code == 422  # below the minimum
        ok = client.put("/api/settings/retention", json={"enabled": True, "scans_days": 30, "history_days": None, "deleted_days": 60, "audit_days": 90}, headers=UI)
        assert ok.status_code == 200 and ok.json()["history_days"] is None
        # a manual clean-up needs the confirmation, and works only when it is switched on
        assert client.post("/api/settings/retention/run", json={}, headers=UI).status_code == 409
        assert client.post("/api/settings/retention/run", json={"confirm": True}, headers=UI).json() == {"removed": {}}
        assert client.get("/api/audit").json()["entries"][0]["action"] == "retention_run"
    finally:
        rt.stop()
