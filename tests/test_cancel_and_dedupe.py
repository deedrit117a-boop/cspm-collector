"""Cancelling runs, the per-account "already running" rule, and the confirmation of very large runs."""
import threading
from pathlib import Path
from zoneinfo import ZoneInfo

import boto3
import mongomock
import pytest
from moto import mock_aws

from cspm_collector.core.config import AccountSettings, ConcurrencySettings, MongoSettings, Settings
from cspm_collector.core.scan import ScanFilter, run_scan
from cspm_collector.core.workers import Task, run_tasks
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store
from cspm_collector.web import app as web_app
from cspm_collector.web.runner import RunManager
from test_web_api import UI, make

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
R = "ap-northeast-2"
TRIG = {"type": "manual", "by": "t"}


def store_():
    s = Store(mongomock.MongoClient()["d"], MongoSettings())
    s.init_db()
    return s


class Gate:
    """run_scan stand-in that holds the run until cancelled / released."""

    def __init__(self):
        self.entered, self.release, self.cancels = threading.Event(), threading.Event(), []

    def __call__(self, settings, spec, store, *, flt, options, scan_id, trigger, cancel=None, **kw):
        self.cancels.append(cancel)
        self.entered.set()
        for _ in range(500):
            if self.release.is_set() or (cancel is not None and cancel.is_set()):
                break
            threading.Event().wait(0.01)
        status = "CANCELLED" if cancel is not None and cancel.is_set() else "COMPLETED"
        store.create_scan(scan_id, [], "v", None, {"trigger": trigger})
        store.finish_scan(scan_id, status, {})


@pytest.fixture
def two():
    settings = Settings(accounts=[AccountSettings(account_id="1", regions=[R]), AccountSettings(account_id="2", regions=[R]),
                                  AccountSettings(account_id="3", regions=[R])])
    gate = Gate()
    runner = RunManager(store_(), lambda: settings, lambda: load_spec(SPEC), run_fn=gate)
    runner.start()
    yield runner, gate
    gate.release.set()
    runner.stop()


# ----------------------------------------------------------------------------------- same item, other account
def test_the_same_item_may_run_for_another_account(two):
    runner, gate = two
    first = runner.submit(["sqs"], TRIG, accounts=["1"])
    assert first.accepted == ["sqs"] and gate.entered.wait(2)
    other = runner.submit(["sqs"], TRIG, accounts=["2"])  # sqs of account 1 is running, account 2 is free
    assert other.accepted == ["sqs"] and other.skipped == {}
    again = runner.submit(["sqs"], TRIG, accounts=["1"])
    assert again.scan_id is None and again.skipped == {"sqs": "이미 실행 중"}
    queued_again = runner.submit(["sqs"], TRIG, accounts=["2"])
    assert queued_again.scan_id is None and queued_again.skipped == {"sqs": "이미 대기 중"}


def test_only_the_free_accounts_are_queued_and_services_with_the_same_free_accounts_share_a_run(two):
    runner, gate = two
    runner.submit(["sqs"], TRIG, accounts=["1"])
    assert gate.entered.wait(2)
    sub = runner.submit(["sqs", "sns"], TRIG, accounts=["1", "2"])  # sqs: only 2 is free; sns: both
    assert sub.skipped == {} and len(sub.scan_ids) == 2 and sub.accepted == ["sqs", "sns"]
    queued = {tuple(q["services"]): q["accounts"] for q in runner.state()["queued"]}
    assert queued == {("sqs",): ["2"], ("sns",): ["1", "2"]}


def test_all_accounts_means_the_accounts_that_are_still_free(two):
    runner, gate = two
    runner.submit(["sqs"], TRIG, accounts=["1"])
    assert gate.entered.wait(2)
    sub = runner.submit(["sqs"], TRIG)  # every account: 1 is taken, so 2 and 3
    assert sub.accepted == ["sqs"] and runner.state()["queued"][0]["accounts"] == ["2", "3"]


def test_akamai_is_one_unit_whatever_accounts_are_chosen():
    from cspm_collector.core.config import AkamaiAccountSettings
    settings = Settings(accounts=[AccountSettings(account_id="1", regions=[R]), AccountSettings(account_id="2", regions=[R])],
                        akamai=[AkamaiAccountSettings(name="main", env_prefix="X")])
    gate = Gate()
    runner = RunManager(store_(), lambda: settings, lambda: load_spec(SPEC), run_fn=gate)
    runner.start()
    try:
        assert runner.submit(["akamai"], TRIG, accounts=["1"]).accepted == ["akamai"] and gate.entered.wait(2)
        assert runner.submit(["akamai"], TRIG, accounts=["2"]).skipped == {"akamai": "이미 실행 중"}
    finally:
        gate.release.set()
        runner.stop()


# ----------------------------------------------------------------------------------- cancel
def test_a_queued_run_can_be_cancelled_and_leaves_the_queue(two):
    runner, gate = two
    runner.submit(["sqs"], TRIG, accounts=["1"])
    assert gate.entered.wait(2)
    queued = runner.submit(["sns"], TRIG, accounts=["1"])
    assert runner.cancel(queued.scan_id) == "queued" and runner.state()["queued"] == []
    assert runner.cancel(queued.scan_id) is None and runner.cancel("nope") is None


def test_a_running_run_gets_its_cancel_event_set_and_ends_cancelled(two):
    runner, gate = two
    sub = runner.submit(["sqs"], TRIG)
    assert gate.entered.wait(2) and not gate.cancels[0].is_set()
    assert runner.cancel(sub.scan_id) == "running" and runner.state()["running"]["cancelling"] is True
    assert runner.wait_idle(5)
    assert runner.store.coll("scans").find_one({"scan_id": sub.scan_id})["status"] == "CANCELLED"


def test_run_tasks_starts_nothing_new_after_cancel_but_lets_running_tasks_finish():
    stop, ran = threading.Event(), []

    def work(task):
        ran.append(task.region)
        if task.region == "r0":
            stop.set()  # the first task asks for the stop while it runs
        return task

    tasks = [Task("a", f"r{i}", "s") for i in range(20)]
    from cspm_collector.core.config import ConcurrencySettings as C
    out = run_tasks(tasks, work, C(total=1, per_account=1, per_service=1), cancelled=stop.is_set)
    assert ran == ["r0"] and len(out) == 1


def test_a_cancelled_scan_is_marked_cancelled_and_deletes_nothing():
    with mock_aws():
        settings = Settings(accounts=[AccountSettings(account_id="123456789012", regions=[R])],
                            concurrency=ConcurrencySettings(total=2, per_account=2, per_service=2))
        store = store_()
        boto3.client("sqs", region_name=R).create_queue(QueueName="q1")
        spec = load_spec(SPEC)
        first = run_scan(settings, spec, store, flt=ScanFilter(services={"sqs"}))
        assert first.status == "COMPLETED"
        assert store.coll("resources").count_documents({"service": "sqs", "deleted_at": None}) == 1
        boto3.client("sqs", region_name=R).delete_queue(QueueUrl=boto3.client("sqs", region_name=R).list_queues()["QueueUrls"][0])
        stop = threading.Event()
        stop.set()  # stopped before any task could start
        cancelled = run_scan(settings, spec, store, flt=ScanFilter(services={"sqs"}), cancel=stop)
        assert cancelled.status == "CANCELLED" and cancelled.tasks == 1
        assert store.coll("scans").find_one({"scan_id": cancelled.scan_id})["status"] == "CANCELLED"
        # the queue is gone in AWS, but a cancelled run must not soft-delete what it did not get to read
        assert store.coll("resources").count_documents({"service": "sqs", "deleted_at": None}) == 1


# ----------------------------------------------------------------------------------- the endpoints
def test_cancel_endpoint_for_a_queued_run_and_for_an_unknown_one():
    client, rt, stub, _ = make()
    try:
        stub.gate = threading.Event()
        client.post("/api/runs", json={"services": ["sqs"]}, headers=UI)
        assert stub.entered.wait(2)
        second = client.post("/api/runs", json={"services": ["sns"]}, headers=UI).json()
        assert client.post(f"/api/runs/{second['scan_id']}/cancel").status_code == 403  # needs the UI header
        r = client.post(f"/api/runs/{second['scan_id']}/cancel", headers=UI)
        assert r.status_code == 200 and r.json()["cancelled"] == "queued"
        assert client.post("/api/runs/unknown/cancel", headers=UI).status_code == 404
        assert any(a["action"] == "run_cancel" for a in client.get("/api/audit").json()["entries"])
        stub.gate.set()
    finally:
        rt.stop()


def test_a_very_large_run_needs_a_confirmation(monkeypatch):
    monkeypatch.setattr(web_app, "BIG_RUN_TASKS", 2)
    client, rt, stub, _ = make()
    try:
        r = client.post("/api/runs", json={"services": ["ec2", "ecs", "rds"]}, headers=UI)  # 3 regional items x 2 regions
        assert r.status_code == 409 and r.json()["detail"]["code"] == "CONFIRM_NEEDED"
        d = r.json()["detail"]
        assert d["tasks"] == 6 and d["limit"] == 2 and d["accounts"] == 1 and d["approx"] is False and stub.calls == []
        ok = client.post("/api/runs", json={"services": ["ec2", "ecs", "rds"], "confirm": True}, headers=UI)
        assert ok.status_code == 202 and rt.runner.wait_idle()
        assert client.post("/api/runs", json={"services": ["s3"]}, headers=UI).status_code == 202  # 1 task: under the limit
    finally:
        rt.stop()
