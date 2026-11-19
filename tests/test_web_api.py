import threading
from pathlib import Path

import boto3
import mongomock
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from cspm_collector.core.config import AccountSettings, AkamaiAccountSettings, MongoSettings, Settings
from cspm_collector.storage.store import Store
from cspm_collector.web.server import build_runtime

SPEC = str(Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml")
UI = {"X-CSPM-UI": "1"}


class Stub:
    """run_scan stand-in that records calls and writes a finished scan with per-service stats."""

    def __init__(self):
        self.calls, self.gate, self.entered = [], None, threading.Event()

    def __call__(self, settings, spec, store, *, flt, options, scan_id, trigger, **kw):
        self.calls.append({"services": sorted(flt.services), "trigger": trigger, "flags": sorted(options.flags),
                           "per_resource": options.per_resource_workers,
                           "accounts": sorted(flt.accounts) if flt.accounts else None})
        self.entered.set()
        if self.gate:
            self.gate.wait(5)
        store.create_scan(scan_id, ["1"], "v", None, {"services": sorted(flt.services), "trigger": trigger})
        store.finish_scan(scan_id, "COMPLETED", {
            "tasks": 3, "resources": {"inserted": 5, "updated": 1, "unchanged": 4}, "api_calls": 42, "swept": 0,
            "services": {s: {"tasks": 1, "resources": 10, "seconds": 2.5} for s in flt.services}})


def make(token=None, user_header=None, akamai=False, stub=None, more_accounts=False):
    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()
    settings = Settings(accounts=[AccountSettings(account_id="111", name="dev", regions=["ap-northeast-2", "us-east-1"])])
    if more_accounts:
        settings.accounts += [AccountSettings(account_id="222", name="dev2", env="dev", regions=["ap-northeast-2"]),
                              AccountSettings(account_id="333", name="prod1", env="prod", regions=["ap-northeast-2"])]
    if akamai:
        settings.akamai = [AkamaiAccountSettings(name="main", env_prefix="X")]
    stub = stub or Stub()
    rt = build_runtime(settings, store, spec_path=SPEC, run_fn=stub, token=token, user_header=user_header,
                       allowed_hosts=("127.0.0.1", "localhost", "testserver"))
    rt.runner.start()
    return TestClient(rt.app), rt, stub, store


@pytest.fixture
def web():
    client, rt, stub, store = make()
    yield client, rt, stub, store
    rt.stop()


def items(client):
    return {i["service"]: i for i in client.get("/api/items").json()["items"]}


# ----------------------------------------------------------------------------- protection
def test_token_is_required_when_configured():
    client, rt, *_ = make(token="s3cret")
    try:
        assert client.get("/api/health").status_code == 200  # liveness stays open
        assert client.get("/api/items").status_code == 401
        assert client.get("/api/items", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get("/api/items", headers={"Authorization": "Bearer s3cret"}).status_code == 200
        assert client.get("/api/items", headers={"X-CSPM-Token": "s3cret"}).status_code == 200
        assert client.get("/api/overview", headers={"X-CSPM-Token": "s3cret"}).json()["auth"] is True
    finally:
        rt.stop()


def test_changing_requests_need_the_ui_header_and_foreign_hosts_are_refused(web):
    client, *_ = web
    body = {"auto": True, "schedule": {"kind": "daily", "time": "03:00"}}
    assert client.put("/api/items/sqs/schedule", json=body).status_code == 403  # a foreign web page cannot send this
    assert client.put("/api/items/sqs/schedule", json=body, headers=UI).status_code == 200
    assert client.post("/api/runs", json={"services": ["sqs"]}).status_code == 403
    assert client.get("/api/items", headers={"Host": "evil.example.com"}).status_code == 400  # DNS rebinding


# ----------------------------------------------------------------------------- overview and items
def test_overview_shows_accounts_concurrency_and_limits(web):
    client, *_ = web
    o = client.get("/api/overview").json()
    assert o["timezone"] == "Asia/Seoul" and o["akamai"] == [] and o["run"]["running"] is None
    assert o["accounts"] == [{"account_id": "111", "name": "dev", "env": None, "regions": ["ap-northeast-2", "us-east-1"],
                               "profile": None, "role_arn": None, "external_id_env": None, "source": "file"}]
    assert o["concurrency"] == {"total": 32, "per_account": 8, "per_service": 4, "per_resource": 8}
    assert o["concurrency_limits"]["per_resource"] == [1, 64]


def test_items_list_with_task_estimates_and_defaults(web):
    client, *_ = web
    it = items(client)
    assert len(it) == 93 and "resourcegroupstaggingapi" not in it  # only enabled services
    assert it["s3"]["scope"] == "global" and it["s3"]["tasks"] == 1  # one task per account
    assert it["ec2"]["scope"] == "regional" and it["ec2"]["tasks"] == 2  # one per configured region
    assert it["ec2"]["auto"] is False and it["ec2"]["schedule_text"] == "수동만" and it["ec2"]["state"] == "idle"
    assert it["ec2"]["last_run"] is None and it["ec2"]["next_run"] is None
    assert it["sagemaker"]["opt_in_flags"] == ["--collect-sagemaker-jobs"]
    tiers = [i["tier"] for i in client.get("/api/items").json()["items"]]
    assert tiers == sorted(tiers)


def test_regions_discovered_at_run_time_have_no_fixed_estimate():
    client, rt, *_ = make()
    rt.stop()
    store = Store(mongomock.MongoClient()["d2"], MongoSettings())
    store.init_db()
    settings = Settings(accounts=[AccountSettings(account_id="1")])  # no region list: "all enabled regions"
    rt2 = build_runtime(settings, store, spec_path=SPEC, allowed_hosts=("testserver",))
    got = {i["service"]: i for i in TestClient(rt2.app).get("/api/items").json()["items"]}
    assert got["s3"]["tasks"] == 1 and got["ec2"]["tasks"] is None


def test_akamai_item_exists_only_when_configured():
    client, rt, *_ = make(akamai=True)
    try:
        akamai = items(client)["akamai"]
        assert akamai["source"] == "akamai" and akamai["tasks"] == 1 and akamai["tier"] == 1
        assert client.put("/api/items/akamai/schedule", headers=UI,
                          json={"auto": False, "schedule": {"kind": "manual"}}).status_code == 200
    finally:
        rt.stop()
    c2, rt2, *_ = make()
    try:
        assert "akamai" not in items(c2)
    finally:
        rt2.stop()


# ----------------------------------------------------------------------------- schedules
def test_saving_a_schedule_shows_text_next_run_and_is_logged(web):
    client, *_ = web
    body = {"auto": True, "schedule": {"kind": "weekly", "time": "03:00", "weekdays": [0, 2]}}
    saved = client.put("/api/items/rds/schedule", json=body, headers=UI).json()
    assert saved["auto"] is True and saved["next_run"].endswith("Z")
    row = items(client)["rds"]
    assert row["auto"] and row["schedule_text"] == "매주 월·수 03:00" and row["next_run"] == saved["next_run"]
    assert row["schedule"]["weekdays"] == [0, 2]
    audit = client.get("/api/audit").json()["entries"][0]
    assert audit["action"] == "schedule" and audit["detail"]["service"] == "rds" and audit["user"] == "local"


def test_clearing_the_auto_checkbox_stops_the_schedule_but_keeps_the_setting(web):
    client, *_ = web
    sched = {"kind": "daily", "time": "05:30"}
    client.put("/api/items/rds/schedule", json={"auto": True, "schedule": sched}, headers=UI)
    client.put("/api/items/rds/schedule", json={"auto": False, "schedule": sched}, headers=UI)
    row = items(client)["rds"]
    assert row["auto"] is False and row["next_run"] is None and row["schedule_text"] == "매일 05:30"


def test_invalid_schedules_and_unknown_items_are_rejected(web):
    client, *_ = web
    bad = client.put("/api/items/rds/schedule", headers=UI, json={"auto": True, "schedule": {"kind": "daily", "time": "99:00"}})
    assert bad.status_code == 422
    assert client.put("/api/items/rds/schedule", headers=UI,
                      json={"auto": True, "schedule": {"kind": "minutes", "every_minutes": 2}}).status_code == 422
    assert client.put("/api/items/nope/schedule", headers=UI,
                      json={"auto": True, "schedule": {"kind": "manual"}}).status_code == 404


def test_bulk_schedule_applies_to_every_selected_item(web):
    client, *_ = web
    res = client.post("/api/items/schedule", headers=UI, json={
        "services": ["sqs", "sns", "kms"], "auto": True, "schedule": {"kind": "minutes", "every_minutes": 60}})
    assert res.json()["updated"] == ["sqs", "sns", "kms"]
    it = items(client)
    assert all(it[s]["auto"] and it[s]["schedule_text"] == "1시간마다" for s in ("sqs", "sns", "kms"))
    assert not it["ec2"]["auto"]
    unknown = client.post("/api/items/schedule", headers=UI, json={
        "services": ["sqs", "nope"], "auto": True, "schedule": {"kind": "manual"}})
    assert unknown.status_code == 404 and items(client)["sqs"]["schedule_text"] == "1시간마다"  # all or nothing


# ----------------------------------------------------------------------------- runs
def test_manual_run_history_and_last_result_per_item(web):
    client, rt, stub, store = web
    res = client.post("/api/runs", json={"services": ["sqs", "sns"]}, headers={**UI, "X-Forwarded-User": "ignored"})
    assert res.status_code == 202
    body = res.json()
    assert body["accepted"] == ["sqs", "sns"] and body["skipped"] == {}
    assert rt.runner.wait_idle()
    assert stub.calls[0]["trigger"] == {"type": "manual", "by": "local"}

    run = client.get("/api/runs").json()["runs"][0]
    assert run["scan_id"] == body["scan_id"] and run["status"] == "COMPLETED"
    assert (run["resources"], run["inserted"], run["updated"], run["unchanged"], run["api_calls"]) == (10, 5, 1, 4, 42)
    assert run["started_at"].endswith("Z") and run["services"] == ["sns", "sqs"]

    last = items(client)["sqs"]["last_run"]
    assert last["scan_id"] == body["scan_id"] and last["resources"] == 10 and last["seconds"] == 2.5

    detail = client.get(f"/api/runs/{body['scan_id']}").json()
    assert {s["service"] for s in detail["services"]} == {"sqs", "sns"} and detail["summary"]["tasks"] == 3


def test_a_running_item_cannot_be_started_again_and_shows_its_state(web):
    client, rt, stub, _ = web
    stub.gate = threading.Event()
    first = client.post("/api/runs", json={"services": ["sqs"]}, headers=UI).json()
    assert stub.entered.wait(2)
    assert items(client)["sqs"]["state"] == "running"
    dup = client.post("/api/runs", json={"services": ["sqs"]}, headers=UI)
    assert dup.status_code == 409 and dup.json()["detail"]["skipped"] == {"sqs": "이미 실행 중"}
    queued = client.post("/api/runs", json={"services": ["sqs", "sns"]}, headers=UI).json()
    assert queued["accepted"] == ["sns"] and queued["skipped"] == {"sqs": "이미 실행 중"}
    assert items(client)["sns"]["state"] == "queued"
    overview = client.get("/api/overview").json()["run"]
    assert overview["running"]["scan_id"] == first["scan_id"] and len(overview["queued"]) == 1
    assert client.get(f"/api/runs/{queued['scan_id']}").json()["status"] == "QUEUED"
    stub.gate.set()
    assert rt.runner.wait_idle()
    assert client.get(f"/api/runs/{first['scan_id']}").json()["status"] == "COMPLETED"


def test_run_requests_are_validated(web):
    client, *_ = web
    assert client.post("/api/runs", json={"services": []}, headers=UI).status_code == 422
    assert client.post("/api/runs", json={"services": ["nope"]}, headers=UI).status_code == 409
    assert client.post("/api/runs", json={"services": ["sqs"], "flags": ["--rm-rf"]}, headers=UI).status_code == 422
    ok = client.post("/api/runs", json={"services": ["sagemaker"], "flags": ["--collect-sagemaker-jobs"]}, headers=UI)
    assert ok.status_code == 202
    assert client.get("/api/runs/does-not-exist").status_code == 404


def test_concurrency_can_be_changed_and_reaches_the_next_run(web):
    client, rt, stub, _ = web
    new = {"total": 16, "per_account": 4, "per_service": 2, "per_resource": 24}
    assert client.put("/api/settings/concurrency", json=new, headers=UI).json() == new
    assert client.get("/api/settings/concurrency").json() == new
    assert client.get("/api/overview").json()["concurrency"] == new
    for bad in ({**new, "per_resource": 0}, {**new, "total": 1000}, {"total": 4}):
        assert client.put("/api/settings/concurrency", json=bad, headers=UI).status_code == 422
    client.post("/api/runs", json={"services": ["sqs"]}, headers=UI)
    assert rt.runner.wait_idle() and stub.calls[0]["per_resource"] == 8  # the stub ignores settings...
    # ...so check what a real run would be given
    assert rt.runner._load_settings().concurrency.per_resource == 24


def test_the_proxy_user_is_recorded_when_configured():
    client, rt, *_ = make(user_header="X-Forwarded-User")
    try:
        client.post("/api/runs", json={"services": ["sqs"]}, headers={**UI, "X-Forwarded-User": "heejim"})
        assert rt.runner.wait_idle()
        assert client.get("/api/audit").json()["entries"][0]["user"] == "heejim"
        assert client.get("/api/runs").json()["runs"][0]["trigger"] == {"type": "manual", "by": "heejim"}
    finally:
        rt.stop()


# ----------------------------------------------------------------------------- a real collection through the page
def test_a_real_scan_started_from_the_page_fills_the_history():
    from cspm_collector.core.scan import run_scan

    with mock_aws():
        boto3.client("sqs", region_name="ap-northeast-2").create_queue(QueueName="q1")
        boto3.client("sns", region_name="ap-northeast-2").create_topic(Name="t1")
        store = Store(mongomock.MongoClient()["d"], MongoSettings())
        store.init_db()
        settings = Settings(accounts=[AccountSettings(account_id="123456789012", regions=["ap-northeast-2"])])
        rt = build_runtime(settings, store, spec_path=SPEC, run_fn=run_scan, allowed_hosts=("testserver",))
        rt.runner.start()
        client = TestClient(rt.app)
        try:
            client.put("/api/settings/concurrency", headers=UI, json={"total": 4, "per_account": 2, "per_service": 2, "per_resource": 3})
            sub = client.post("/api/runs", json={"services": ["sqs", "sns"]}, headers=UI).json()
            assert rt.runner.wait_idle(20)
            run = client.get("/api/runs").json()["runs"][0]
            assert run["status"] == "COMPLETED" and run["resources"] == 2 and run["inserted"] == 2 and run["tasks"] == 2
            assert run["trigger"] == {"type": "manual", "by": "local"} and run["seconds"] >= 0
            detail = client.get(f"/api/runs/{sub['scan_id']}").json()
            by_service = {s["service"]: s for s in detail["services"]}
            assert by_service["sqs"]["resources"] == 1 and by_service["sns"]["resources"] == 1
            assert detail["progress"]["done"] == detail["progress"]["total"] == 2 and detail["progress"]["running"] == []
            assert detail["options"]["concurrency"]["per_resource"] == 3  # the setting reached the real run
            last = {i["service"]: i for i in client.get("/api/items").json()["items"]}["sqs"]["last_run"]
            assert last["resources"] == 1 and last["status"] == "COMPLETED"
        finally:
            rt.stop()


def test_server_tells_its_api_level_so_the_page_can_warn_about_an_old_server(web):
    from cspm_collector.web.app import API_LEVEL
    client, *_ = web
    assert client.get("/api/health").json() == {"ok": True, "api_level": API_LEVEL}
    assert client.get("/api/overview").json()["api_level"] == API_LEVEL


def test_detail_of_a_run_the_worker_took_but_has_not_recorded_yet_is_not_a_404(web):
    """Between the queue and the first write of the scan record the page may already ask for the run's detail."""
    client, rt, stub, _ = web
    stub.gate = threading.Event()  # the stub writes its scan record only after the gate: the worker is busy, no record
    first = client.post("/api/runs", json={"services": ["sqs"]}, headers=UI).json()
    assert stub.entered.wait(2)
    r = client.get(f"/api/runs/{first['scan_id']}")
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "RUNNING" and d["live"] is True and d["account_stats"] == [] and d["summary"] == {} and d["problems"] == []
    assert client.get("/api/runs/20200101T000000Z-nope").status_code == 404  # an unknown run is still a 404
    stub.gate.set()
    assert rt.runner.wait_idle()
