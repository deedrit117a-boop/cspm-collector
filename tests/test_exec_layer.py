"""What the control page needs from run_scan: progress, per-service numbers, trigger, stale-run cleanup."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import boto3
import mongomock
import pytest
from moto import mock_aws

from cspm_collector.collectors.base import CollectOptions
from cspm_collector.core.config import AccountSettings, ConcurrencySettings, MongoSettings, Settings
from cspm_collector.core.scan import ScanFilter, run_scan
from cspm_collector.core.workers import Task, run_tasks
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
R = "ap-northeast-2"


@pytest.fixture
def env():
    with mock_aws():
        settings = Settings(accounts=[AccountSettings(account_id="123456789012", regions=[R])],
                            concurrency=ConcurrencySettings(total=4, per_account=2, per_service=2, per_resource=3))
        store = Store(mongomock.MongoClient()["d"], MongoSettings())
        store.init_db()
        yield settings, load_spec(SPEC), store


def test_scan_records_per_service_numbers_progress_and_context(env):
    settings, spec, store = env
    boto3.client("sqs", region_name=R).create_queue(QueueName="q1")
    boto3.client("sns", region_name=R).create_topic(Name="t1")
    boto3.client("sns", region_name=R).create_topic(Name="t2")
    s = run_scan(settings, spec, store, flt=ScanFilter(services={"sqs", "sns"}),
                 trigger={"type": "manual", "by": "alice"})
    scan = store.coll("scans").find_one({"scan_id": s.scan_id})
    stats = scan["summary"]["services"]
    assert stats["sqs"]["resources"] == 1 and stats["sns"]["resources"] == 2
    assert stats["sns"]["tasks"] == 1 and stats["sns"]["seconds"] >= 0
    assert scan["progress"]["done"] == scan["progress"]["total"] == 2 and scan["progress"]["running"] == []
    assert scan["options"]["trigger"] == {"type": "manual", "by": "alice"}
    assert scan["options"]["concurrency"] == {"total": 4, "per_account": 2, "per_service": 2, "per_resource": 3}


def test_the_cli_default_trigger_is_recorded(env):
    settings, spec, store = env
    s = run_scan(settings, spec, store, flt=ScanFilter(services={"sqs"}))
    assert store.coll("scans").find_one({"scan_id": s.scan_id})["options"]["trigger"] == {"type": "cli"}


def test_per_resource_setting_reaches_the_collectors(env):
    settings, spec, store = env
    seen = []
    from cspm_collector.collectors.generic import GenericCollector

    real = GenericCollector.collect

    def spy(self, ctx):
        seen.append(ctx.options.per_resource_workers)
        return real(self, ctx)

    with mock.patch.object(GenericCollector, "collect", spy):
        run_scan(settings, spec, store, flt=ScanFilter(services={"sns"}), options=CollectOptions(per_resource_workers=99))
    assert seen == [3]  # the settings win over whatever the options carried


def test_progress_is_visible_while_tasks_are_running(env):
    """The page polls the scan record: it must change as tasks start and finish, not only at the end."""
    settings, spec, store = env
    snapshots = []
    real = store.update_progress

    def spy(scan_id, done, total, running, accounts=None):
        snapshots.append((done, total, tuple(running)))
        real(scan_id, done, total, running, accounts)

    store.update_progress = spy
    run_scan(settings, spec, store, flt=ScanFilter(services={"sqs", "sns"}))
    assert snapshots[0] == (0, 2, ())  # announced before anything runs
    assert snapshots[-1][:2] == (2, 2) and snapshots[-1][2] == ()
    assert any(r for _, _, r in snapshots)  # some snapshot listed a running service
    assert [s[0] for s in snapshots] == sorted(s[0] for s in snapshots)  # never goes backwards


def test_on_start_hook_fires_once_per_task_on_the_calling_thread():
    import threading

    started, main = [], threading.get_ident()

    def on_start(task):
        started.append((task.service, threading.get_ident() == main))

    run_tasks([Task("a", "r", "x"), Task("a", "r", "y")], lambda t: None, ConcurrencySettings(total=2), on_start=on_start)
    assert sorted(started) == [("x", True), ("y", True)]


# ----------------------------------------------------------------------------- stale runs
def test_only_silent_running_scans_are_marked_interrupted(env):
    _, _, store = env
    now = datetime.now(timezone.utc)
    old, recent = now - timedelta(hours=2), now - timedelta(minutes=2)
    for sid, started, progress in [("silent", old, old), ("alive", old, recent), ("never-reported", old, None)]:
        store.create_scan(sid, [], "v")
        patch = {"started_at": started.replace(tzinfo=None)}
        if progress:
            patch["progress"] = {"done": 1, "total": 5, "running": [], "updated_at": progress.replace(tzinfo=None)}
        store.coll("scans").update_one({"scan_id": sid}, {"$set": patch})
    store.create_scan("fresh", [], "v")  # just started, no progress yet
    assert store.interrupt_stale_scans(now=now) == 2
    status = {d["scan_id"]: d["status"] for d in store.coll("scans").find({})}
    assert status == {"silent": "INTERRUPTED", "alive": "RUNNING", "never-reported": "INTERRUPTED", "fresh": "RUNNING"}
    assert store.coll("scans").find_one({"scan_id": "silent"})["finished_at"] is not None


# ----------------------------------------------------------------------------- per-account results
def test_scan_records_what_each_account_collected_and_how_it_went():
    with mock_aws():
        boto3.client("sqs", region_name=R).create_queue(QueueName="q1")
        boto3.client("sns", region_name=R).create_topic(Name="t1")
        boto3.client("sns", region_name=R).create_topic(Name="t2")
        settings = Settings(accounts=[AccountSettings(account_id="123456789012", name="ambient", regions=[R]),
                                      AccountSettings(account_id="999999999999", name="foreign", regions=[R])],
                            concurrency=ConcurrencySettings(total=4, per_account=2, per_service=2))
        store = Store(mongomock.MongoClient()["d"], MongoSettings())
        store.init_db()
        s = run_scan(settings, load_spec(SPEC), store, flt=ScanFilter(services={"sqs", "sns"}))
        accts = store.scan_accounts(s.scan_id)
        assert "accounts" not in store.coll("scans").find_one({"scan_id": s.scan_id})["summary"]  # not in the scan document
        ok, bad = accts["123456789012"], accts["999999999999"]
        assert ok["tasks"] == 2 and ok["resources"] == 3 and ok["status"] == "COMPLETED"
        assert ok["services"]["sns"]["resources"] == 2 and ok["services"]["sqs"]["resources"] == 1
        assert ok["services"]["sns"]["failed"] == 0 and ok["services"]["sqs"]["failed"] == 0  # failed API rows per item (freshness)
        assert ok["seconds"] >= 0 and ok["statuses"]["SUCCESS"] > 0
        # an account that could not even be opened is listed with its reason, not silently missing
        assert bad["tasks"] == 0 and bad["resources"] == 0 and bad["status"] == "FAILED"
        assert "AccountMismatch" in bad["error"] and "999999999999" in bad["error"]


def test_progress_tells_how_far_each_account_is(env):
    settings, spec, store = env
    seen = []
    real = store.update_progress

    def spy(scan_id, done, total, running, accounts=None):
        seen.append(accounts)
        real(scan_id, done, total, running, accounts)

    store.update_progress = spy
    s = run_scan(settings, spec, store, flt=ScanFilter(services={"sqs", "sns"}))
    assert seen[0] == {"123456789012": {"done": 0, "total": 2}}
    assert seen[-1] == {"123456789012": {"done": 2, "total": 2}}
    assert store.coll("scans").find_one({"scan_id": s.scan_id})["progress"]["accounts"]["123456789012"] == {"done": 2, "total": 2}
