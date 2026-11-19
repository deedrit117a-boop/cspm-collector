"""Groups of items and accounts, and running / scheduling for a selection of accounts."""
from datetime import datetime, timedelta, timezone

import pytest

from cspm_collector.web.scheduler import Scheduler

from test_web_api import UI, Stub, items, make


@pytest.fixture
def web():
    client, rt, stub, store = make(more_accounts=True)
    yield client, rt, stub, store
    rt.stop()


def create(client, kind, name, members):
    return client.post("/api/groups", json={"kind": kind, "name": name, "members": members}, headers=UI)


# ----------------------------------------------------------------------------- group CRUD
def test_create_list_rename_add_remove_and_delete_an_item_group(web):
    client, *_ = web
    r = create(client, "items", "네트워크", ["ec2", "elbv2"])
    assert r.status_code == 201 and r.json()["members"] == ["ec2", "elbv2"]
    gid = r.json()["id"]
    assert [g["name"] for g in client.get("/api/groups").json()["items"]] == ["네트워크"]

    r = client.put(f"/api/groups/{gid}", json={"name": "네트워크 서비스", "add": ["route53", "ec2"], "remove": ["elbv2"]}, headers=UI)
    assert r.status_code == 200 and r.json()["members"] == ["ec2", "route53"] and r.json()["name"] == "네트워크 서비스"
    r = client.put(f"/api/groups/{gid}", json={"members": ["sqs"]}, headers=UI)  # replace the whole list
    assert r.json()["members"] == ["sqs"]

    assert client.delete(f"/api/groups/{gid}", headers=UI).json()["deleted"] == gid
    assert client.get("/api/groups").json()["items"] == []
    assert client.delete(f"/api/groups/{gid}", headers=UI).status_code == 404


def test_group_rules_unknown_members_duplicate_names_and_kind(web):
    client, *_ = web
    assert create(client, "items", "g", ["nope"]).status_code == 422  # not a collection item
    assert create(client, "items", "g", ["111"]).status_code == 422  # an account id is not an item
    assert create(client, "accounts", "a", ["999"]).status_code == 422  # not a configured account
    assert create(client, "other", "a", []).status_code == 422
    assert create(client, "items", "  ", []).status_code == 422
    assert create(client, "items", "g", ["sqs"]).status_code == 201
    assert create(client, "items", "g", ["sns"]).status_code == 422  # same name, same kind
    assert create(client, "accounts", "g", ["111"]).status_code == 201  # the same name may exist for the other kind
    assert client.post("/api/groups", json={"kind": "items", "name": "x"}).status_code == 403  # needs the UI header


def test_env_label_makes_a_builtin_account_group(web):
    client, *_ = web
    groups = {g["name"]: g for g in client.get("/api/groups").json()["accounts"]}
    assert groups["dev 전체"]["members"] == ["222"] and groups["dev 전체"]["builtin"] is True
    assert groups["prod 전체"]["id"] == "env:prod"
    assert client.put("/api/groups/env:dev", json={"add": ["111"]}, headers=UI).status_code == 404  # not editable


# ----------------------------------------------------------------------------- manual runs
def test_run_for_selected_accounts_and_item_groups(web):
    client, rt, stub, _ = web
    gid = create(client, "items", "q", ["sqs", "sns"]).json()["id"]
    ag = create(client, "accounts", "A", ["111", "333"]).json()["id"]
    r = client.post("/api/runs", json={"item_groups": [gid], "services": ["ec2"],
                                       "target": {"accounts": ["222"], "account_groups": [ag]}}, headers=UI)
    assert r.status_code == 202 and sorted(r.json()["accepted"]) == ["ec2", "sns", "sqs"]
    assert rt.runner.wait_idle()
    assert stub.calls[0]["accounts"] == ["111", "222", "333"]


def test_run_without_target_means_all_accounts_and_bad_targets_are_refused(web):
    client, rt, stub, _ = web
    assert client.post("/api/runs", json={"services": ["sqs"]}, headers=UI).status_code == 202
    assert rt.runner.wait_idle() and stub.calls[0]["accounts"] is None
    for target in ({"accounts": ["999"]}, {"account_groups": ["nope"]}):
        assert client.post("/api/runs", json={"services": ["sns"], "target": target}, headers=UI).status_code == 422
    empty = create(client, "accounts", "empty", []).json()["id"]
    assert client.post("/api/runs", json={"services": ["sns"], "target": {"account_groups": [empty]}},
                       headers=UI).status_code == 422  # an empty group must not widen to "all"
    assert client.post("/api/runs", json={}, headers=UI).status_code == 422  # nothing selected
    assert client.post("/api/runs", json={"item_groups": ["nope"]}, headers=UI).status_code == 422
    assert rt.runner.wait_idle() and len(stub.calls) == 1


def test_akamai_still_runs_for_all_its_accounts_when_aws_accounts_are_picked():
    client, rt, stub, _ = make(akamai=True, more_accounts=True)
    try:
        client.post("/api/runs", json={"services": ["akamai", "sqs"], "target": {"accounts": ["222"]}}, headers=UI)
        assert rt.runner.wait_idle() and stub.calls[0]["accounts"] == ["222", "main"]
    finally:
        rt.stop()


def test_run_history_lists_the_accounts(web):
    client, rt, *_ = web
    client.post("/api/runs", json={"services": ["sqs"], "target": {"accounts": ["222"]}}, headers=UI)
    assert rt.runner.wait_idle()
    # the stub writes the scan with account "1"; the real run_scan records the selected account ids
    assert "accounts" in client.get("/api/runs").json()["runs"][0]


# ----------------------------------------------------------------------------- schedules
def test_schedule_keeps_its_account_selection_and_rejects_bad_ones(web):
    client, *_ = web
    body = {"auto": True, "schedule": {"kind": "daily", "time": "03:00"}, "target": {"accounts": ["222"]}}
    assert client.put("/api/items/sqs/schedule", json=body, headers=UI).status_code == 200

    assert items(client)["sqs"]["target"] == {"accounts": ["222"], "account_groups": []}
    assert items(client)["sns"]["target"] == {"accounts": [], "account_groups": []}
    body["target"] = {"accounts": ["999"]}
    assert client.put("/api/items/sqs/schedule", json=body, headers=UI).status_code == 422
    assert items(client)["sqs"]["target"]["accounts"] == ["222"]  # unchanged


def test_scheduler_groups_due_items_by_account_selection_and_follows_group_changes(web):
    client, rt, stub, _ = web
    gid = create(client, "accounts", "devs", ["222"]).json()["id"]
    daily = {"kind": "daily", "time": "03:00"}
    for svc, target in [("sqs", {"account_groups": [gid]}), ("sns", {"account_groups": [gid]}), ("kms", {})]:
        client.put(f"/api/items/{svc}/schedule", json={"auto": True, "schedule": daily, "target": target}, headers=UI)
    client.put(f"/api/groups/{gid}", json={"add": ["333"]}, headers=UI)  # changed after the schedule was saved
    sched = Scheduler(rt.state, rt.runner, rt.state.tz, owner="t")
    later = datetime.now(timezone.utc) + timedelta(days=2)
    res = sched.tick(later)
    assert sorted(res["triggered"]) == ["kms", "sns", "sqs"] and len(res["scan_ids"]) == 2
    assert rt.runner.wait_idle()
    by_services = {tuple(c["services"]): c["accounts"] for c in stub.calls}
    assert by_services == {("sns", "sqs"): ["222", "333"], ("kms",): None}


def test_deleted_group_pauses_the_schedule_instead_of_collecting_everything(web):
    client, rt, stub, _ = web
    gid = create(client, "accounts", "devs", ["222"]).json()["id"]
    client.put("/api/items/sqs/schedule", json={"auto": True, "schedule": {"kind": "daily", "time": "03:00"},
                                                "target": {"account_groups": [gid]}}, headers=UI)
    assert client.delete(f"/api/groups/{gid}", headers=UI).json()["schedules_using_it"] == ["sqs"]
    res = Scheduler(rt.state, rt.runner, rt.state.tz, owner="t").tick(datetime.now(timezone.utc) + timedelta(days=2))
    assert res["triggered"] == [] and "sqs" in res["skipped"]
    assert rt.runner.wait_idle() and stub.calls == []
    assert "알 수 없는 어카운트 그룹" in items_last_skip(client)["sqs"]


def items_last_skip(client):
    return {i["service"]: i["last_skip"] for i in client.get("/api/items").json()["items"]}


def test_the_page_has_the_group_and_account_controls(web):
    client, *_ = web
    html = client.get("/").text
    for element in ("newItemGroup", "newAcctGroup", "pickTarget", "grpDlg", "targetDlg", "bulkgroup", "schedTarget"):
        assert f'id="{element}"' in html


# ----------------------------------------------------------------------------- CSV
def gimp(client, text, apply=False):
    return client.post("/api/groups/import", json={"csv": text, "apply": apply}, headers=UI)


def names(client, kind):
    return {g["name"]: g["members"] for g in client.get("/api/groups").json()[kind] if not g["builtin"]}


def test_groups_csv_creates_changes_and_deletes_in_order(web):
    client, *_ = web
    csv1 = ("kind,name,members,action\n"
            "items,메시징,sqs sns,set\n"
            "items,메시징,kms,add\n"
            "accounts,devs,111;222,set\n")
    r = gimp(client, csv1).json()  # check only
    assert r["applied"] is False and r["counts"]["create"] == 2 and r["counts"]["add"] == 1
    assert names(client, "items") == {}
    assert gimp(client, csv1, apply=True).json()["applied"] is True
    assert names(client, "items") == {"메시징": ["sqs", "sns", "kms"]} and names(client, "accounts") == {"devs": ["111", "222"]}

    csv2 = ("kind,name,members,action\n"
            "items,메시징,sns,remove\n"        # change
            "accounts,devs,333,replace\n"      # replace (Korean/English alias)
            "items,임시,s3,set\n"
            "items,임시,,delete\n")           # created and deleted in the same file
    assert gimp(client, csv2, apply=True).json()["applied"] is True
    assert names(client, "items") == {"메시징": ["sqs", "kms"]} and names(client, "accounts") == {"devs": ["333"]}

    assert gimp(client, "kind,name,action\nitems,메시징,delete\n", apply=True).json()["counts"]["delete"] == 1
    assert names(client, "items") == {}


def test_groups_csv_errors_block_everything_and_are_per_line(web):
    client, *_ = web
    create(client, "items", "keep", ["sqs"])
    bad = ("kind,name,members,action\n"
           "items,new,sqs,set\n"
           "items,keep,nope,add\n"            # unknown member
           "items,missing,sqs,add\n"          # group does not exist
           "other,x,sqs,set\n"                # bad kind
           "items,dev 전체,sqs,set\n"          # fine for items (builtin groups are account groups)
           "accounts,dev 전체,222,set\n"       # builtin account group
           "items,keep,,add\n"                # nothing to add
           "items,keep,sqs,zap\n")            # bad action
    r = gimp(client, bad, apply=True).json()
    assert r["applied"] is False
    errors = {x["line"]: x["error"] for x in r["rows"] if x["error"]}
    assert set(errors) == {3, 4, 5, 7, 8, 9}
    assert "알 수 없는 멤버" in errors[3] and "없는 그룹" in errors[4] and "kind" in errors[5] and "자동 그룹" in errors[7]
    assert names(client, "items") == {"keep": ["sqs"]}  # the valid rows were not applied either


def test_groups_csv_warns_when_a_deleted_group_is_used_by_a_schedule(web):
    client, *_ = web
    gid = create(client, "accounts", "devs", ["222"]).json()["id"]
    client.put("/api/items/sqs/schedule", json={"auto": True, "schedule": {"kind": "daily", "time": "03:00"},
                                                "target": {"account_groups": [gid]}}, headers=UI)
    r = gimp(client, "kind,name,action\naccounts,devs,delete\n").json()
    assert r["rows"][0]["op"] == "delete" and "자동 수집 1개" in r["rows"][0]["message"]


def test_groups_csv_structure_formats_and_export_round_trip(web):
    client, *_ = web
    for text, needle in [("", "헤더"), ("kind,name\n", "헤더"), ("name\nx\n", "kind, name"), ("kind,name,x\nitems,a,1\n", "알 수 없는 열")]:
        r = gimp(client, text)
        assert r.status_code == 422 and needle in r.json()["detail"], (text, r.json())
    assert gimp(client, "kind\tname\tmembers\r\n항목\tg\tsqs sns\r\n", apply=True).json()["applied"] is True  # tabs, Korean kind
    assert names(client, "items") == {"g": ["sqs", "sns"]}
    out = client.get("/api/groups.csv")
    assert out.text.startswith("\ufeffkind,name,members,action") and "items,g,sqs sns,set" in out.text
    assert "dev 전체" not in out.text  # automatic groups are not exported
    assert gimp(client, out.text).json()["counts"]["replace"] == 1
    assert client.post("/api/groups/import", json={"csv": "x"}).status_code == 403


def test_run_detail_lists_every_account_with_its_numbers(web):
    client, rt, stub, store = web
    client.post("/api/runs", json={"services": ["sqs"]}, headers=UI)
    assert rt.runner.wait_idle()
    sid = client.get("/api/runs").json()["runs"][0]["scan_id"]
    store.coll("scans").update_one({"scan_id": sid}, {"$set": {"summary.accounts": {
        "222": {"status": "COMPLETED", "tasks": 1, "resources": 5, "seconds": 1.5, "statuses": {"SUCCESS": 3},
                "services": {"sqs": {"tasks": 1, "resources": 5, "seconds": 1.5}}},
        "111": {"status": "FAILED", "tasks": 0, "resources": 0, "seconds": 0.0, "error": "AccountMismatch: wrong", "services": {}}}}})
    d = client.get(f"/api/runs/{sid}").json()
    by = {a["account_id"]: a for a in d["account_stats"]}
    assert by["222"]["resources"] == 5 and [{k: x[k] for k in ("service", "tasks", "resources", "seconds")} for x in by["222"]["services"]] == [{"service": "sqs", "tasks": 1, "resources": 5, "seconds": 1.5}]
    assert by["111"]["status"] == "FAILED" and "AccountMismatch" in by["111"]["error"]
    assert [a["name"] for a in d["account_stats"]] == sorted(a["name"] for a in d["account_stats"])  # sorted by name


# ----------------------------------------------------------------------------- the log of every account
def _scan_with_log(store, sid="20261026T000000Z-log", summary_accounts=None):
    from cspm_collector.core.errors import Status
    from cspm_collector.storage.records import StatusRecord

    store.create_scan(sid, ["111", "222"], "v", None, {"services": ["ec2", "sqs"], "trigger": {"type": "manual", "by": "t"}})
    rows = [StatusRecord("111", "ap-northeast-2", "ec2", "describe_instances", Status.SUCCESS),
            StatusRecord("111", "ap-northeast-2", "ec2", "describe_volumes", Status.ACCESS_DENIED, error_code="AccessDenied", error="not allowed"),
            StatusRecord("111", "ap-northeast-2", "sqs", "list_queues", Status.SUCCESS),
            StatusRecord("222", "*", "*", "*", Status.ERROR, error_code="AccountMismatch", error="wrong account")]
    store.record_status(sid, rows)
    summary = {"tasks": 2, "resources": {"inserted": 1, "updated": 0, "unchanged": 0}, "api_calls": 3, "swept": 0, "services": {}}
    if summary_accounts is not None:
        summary["accounts"] = summary_accounts
    store.finish_scan(sid, "PARTIAL", summary)
    return sid


def test_detail_with_problem_rows_does_not_crash_and_names_the_account(web):
    client, rt, stub, store = web
    sid = _scan_with_log(store)
    r = client.get(f"/api/runs/{sid}")
    assert r.status_code == 200, r.text  # a name used before it was defined made every run with problems a 500
    d = r.json()
    assert {p["account"] for p in d["problems"]} == {"dev", "dev2"}  # 111 and 222 of the fixture
    assert [p["service"] for p in d["problems"] if p["account_id"] == "111"] == ["ec2"]


def test_each_account_has_its_own_problem_log_and_per_service_api_results(web):
    client, rt, stub, store = web
    sid = _scan_with_log(store, summary_accounts={
        "111": {"status": "PARTIAL", "tasks": 2, "resources": 7, "seconds": 3.0, "statuses": {"SUCCESS": 2, "ACCESS_DENIED": 1},
                "services": {"ec2": {"tasks": 1, "resources": 6, "seconds": 3.0}, "sqs": {"tasks": 1, "resources": 1, "seconds": 1.0}}},
        "222": {"status": "FAILED", "tasks": 0, "resources": 0, "seconds": 0.0, "statuses": {"ERROR": 1}, "error": "AccountMismatch: wrong account",
                "services": {}}})
    by = {a["account_id"]: a for a in client.get(f"/api/runs/{sid}").json()["account_stats"]}
    a = by["111"]
    assert a["has_numbers"] is True and a["resources"] == 7 and a["problem_count"] == 1
    assert [(p["service"], p["api"], p["status"], p["error"]) for p in a["problems"]] == [("ec2", "describe_volumes", "ACCESS_DENIED", "not allowed")]
    svc = {s["service"]: s for s in a["services"]}
    assert svc["ec2"]["statuses"] == {"SUCCESS": 1, "ACCESS_DENIED": 1} and svc["sqs"]["statuses"] == {"SUCCESS": 1} and svc["ec2"]["resources"] == 6
    assert by["222"]["status"] == "FAILED" and by["222"]["error"] and by["222"]["problems"][0]["error_code"] == "AccountMismatch"


def test_runs_from_before_the_per_account_numbers_are_rebuilt_from_the_recorded_log(web):
    client, rt, stub, store = web
    sid = _scan_with_log(store)  # no summary.accounts, as scans of the older versions
    by = {a["account_id"]: a for a in client.get(f"/api/runs/{sid}").json()["account_stats"]}
    assert set(by) == {"111", "222"}
    assert by["111"]["has_numbers"] is False and by["111"]["resources"] is None and by["111"]["status"] == "PARTIAL"
    assert by["222"]["status"] == "FAILED" and by["222"]["problem_count"] == 1
    assert {s["service"]: s["statuses"] for s in by["111"]["services"]} == {"ec2": {"SUCCESS": 1, "ACCESS_DENIED": 1}, "sqs": {"SUCCESS": 1}}


def test_one_noisy_account_cannot_fill_the_log_of_the_others(web):
    from cspm_collector.core.errors import Status
    from cspm_collector.storage.records import StatusRecord
    client, rt, stub, store = web
    sid = _scan_with_log(store)
    store.record_status(sid, [StatusRecord("111", "r", f"svc{n}", "api", Status.ERROR, error_code="E", error="x") for n in range(300)])
    by = {a["account_id"]: a for a in client.get(f"/api/runs/{sid}").json()["account_stats"]}
    assert len(by["111"]["problems"]) == 80 and by["111"]["problem_count"] == 301  # capped log, true count
    assert len(by["222"]["problems"]) == 1


# ----------------------------------------------------------------------------- progress of a running scan
def _running_scan(store):
    from cspm_collector.core.errors import Status
    from cspm_collector.storage.records import StatusRecord

    sid = "20261026T010000Z-live"
    store.create_scan(sid, ["111", "222"], "v", None, {"services": ["ec2", "s3"], "trigger": {"type": "manual", "by": "t"}})  # RUNNING
    store.update_progress(sid, 2, 5, ["ec2"], {"111": {"done": 2, "total": 3}, "222": {"done": 0, "total": 2}})
    store.record_status(sid, [StatusRecord("111", "ap-northeast-2", "ec2", "describe_instances", Status.SUCCESS),
                              StatusRecord("111", "global", "s3", "list_buckets", Status.SUCCESS)])
    return sid


def test_a_running_scan_shows_how_far_each_account_and_item_is(web):
    client, rt, stub, store = web
    d = client.get(f"/api/runs/{_running_scan(store)}").json()
    assert d["live"] is True
    by = {a["account_id"]: a for a in d["account_stats"]}
    assert by["111"]["state"] == "running" and by["111"]["progress"] == {"done": 2, "total": 3}
    assert by["222"]["state"] == "pending" and by["222"]["progress"] == {"done": 0, "total": 2}
    svc = {s["service"]: s for s in by["111"]["services"]}
    assert (svc["ec2"]["done"], svc["ec2"]["total"], svc["ec2"]["state"]) == (1, 2, "running")  # 1 of the 2 regions is in
    assert (svc["s3"]["done"], svc["s3"]["total"], svc["s3"]["state"]) == (1, 1, "done")        # a global item is one task
    # items that were not reached yet are listed as waiting, also for an account that has not started at all
    assert {s["service"]: s["state"] for s in by["222"]["services"]} == {"ec2": "pending", "s3": "pending"}


def test_a_finished_scan_has_no_waiting_items_and_no_live_flag(web):
    client, rt, stub, store = web
    sid = _scan_with_log(store, sid="20261026T020000Z-done")  # finished (finish_scan): only what really ran is listed
    d = client.get(f"/api/runs/{sid}").json()
    assert d["live"] is False
    by = {a["account_id"]: a for a in d["account_stats"]}
    assert by["111"]["state"] is None and {s["service"]: s["state"] for s in by["111"]["services"]} == {"ec2": "done", "sqs": "done"}


def test_the_run_list_carries_the_live_progress_of_each_account(web):
    client, rt, stub, store = web
    _running_scan(store)
    run = [r for r in client.get("/api/runs").json()["runs"] if r["scan_id"].endswith("live")][0]
    assert run["status"] == "RUNNING" and run["progress"]["done"] == 2 and run["progress"]["accounts"]["111"] == {"done": 2, "total": 3}


def test_items_being_collected_right_now_show_as_running_in_an_account_that_is_working(web):
    client, rt, stub, store = web
    sid = _running_scan(store)  # progress.running == ["ec2"]; account 111 is working, 222 has not started
    by = {a["account_id"]: a for a in client.get(f"/api/runs/{sid}").json()["account_stats"]}
    svc111 = {s["service"]: s["state"] for s in by["111"]["services"]}
    assert svc111["ec2"] == "running"  # one of its two regions is in, the other one is being collected
    store.update_progress(sid, 3, 5, ["s3"], {"111": {"done": 2, "total": 3}, "222": {"done": 0, "total": 2}})
    by = {a["account_id"]: a for a in client.get(f"/api/runs/{sid}").json()["account_stats"]}
    assert {s["service"]: s["state"] for s in by["111"]["services"]}["s3"] == "done"      # finished stays finished
    assert {s["service"]: s["state"] for s in by["222"]["services"]}["s3"] == "pending"  # an account that has not started waits
