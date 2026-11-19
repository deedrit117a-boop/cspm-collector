"""Control-page building blocks without HTTP: persisted state, run queue, scheduler."""
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import mongomock
import pytest
from pydantic import ValidationError

from cspm_collector.core.config import AccountSettings, AkamaiAccountSettings, ConcurrencySettings, MongoSettings, Settings
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store
from cspm_collector.web.runner import RunManager
from cspm_collector.web.schedule import Schedule
from cspm_collector.web.scheduler import Scheduler
from cspm_collector.web.state import ConcurrencyUpdate, WebState, naive_utc

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
KST = ZoneInfo("Asia/Seoul")
T = datetime(2026, 10, 22, 9, 0, tzinfo=KST)


def make_store():
    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()
    return store


class Stub:
    """Stands in for run_scan: records the call, creates a finished scan record, can be told to wait or to fail."""

    def __init__(self, store):
        self.store, self.calls = store, []
        self.gate: threading.Event | None = None
        self.entered = threading.Event()
        self.fail: Exception | None = None

    def __call__(self, settings, spec, store, *, flt, options, scan_id, trigger, **kw):
        self.calls.append({"services": sorted(flt.services), "scan_id": scan_id, "trigger": trigger,
                           "flags": sorted(options.flags)})
        self.entered.set()
        if self.gate:
            self.gate.wait(5)
        if self.fail:
            raise self.fail
        store.create_scan(scan_id, [], "v", None, {"trigger": trigger})
        store.finish_scan(scan_id, "COMPLETED", {})


@pytest.fixture
def env():
    store = make_store()
    settings = Settings(accounts=[AccountSettings(account_id="1", regions=["ap-northeast-2"])])
    stub = Stub(store)
    runner = RunManager(store, lambda: settings, lambda: load_spec(SPEC), run_fn=stub)
    runner.start()
    state = WebState(store, KST)
    yield store, settings, stub, runner, state
    runner.stop()


# ---------------------------------------------------------------------------------------------- state
def test_set_schedule_computes_next_run_and_writes_an_audit_entry():
    store = make_store()
    state = WebState(store, KST)
    doc = state.set_schedule("s3", Schedule(kind="daily", time="03:00"), True, "alice", T)
    assert doc["next_run"] == naive_utc(datetime(2026, 10, 23, 3, 0, tzinfo=KST))
    assert state.schedules()["s3"]["updated_by"] == "alice"
    entry = state.recent_audit()[0]
    assert (entry["user"], entry["action"], entry["detail"]["service"]) == ("alice", "schedule", "s3")

    off = state.set_schedule("s3", Schedule(kind="daily", time="03:00"), False, "alice", T)  # checkbox cleared
    assert off["next_run"] is None
    assert state.due(T + timedelta(days=5)) == []


def test_due_only_returns_enabled_schedules_whose_time_has_come():
    state = WebState(make_store(), KST)
    state.set_schedule("a", Schedule(kind="minutes", every_minutes=30), True, "u", T)  # next 09:30
    state.set_schedule("b", Schedule(kind="daily", time="23:00"), True, "u", T)
    state.set_schedule("c", Schedule(kind="manual"), True, "u", T)  # manual: no next run
    assert [d["_id"] for d in state.due(T + timedelta(minutes=29))] == []
    assert [d["_id"] for d in state.due(T + timedelta(minutes=31))] == ["a"]


def test_concurrency_defaults_updates_and_bounds():
    state = WebState(make_store(), KST)
    default = ConcurrencySettings()
    assert state.concurrency(default) == default
    saved = state.set_concurrency(ConcurrencyUpdate(total=16, per_account=4, per_service=2, per_resource=12), "alice", T)
    assert saved.per_resource == 12 and state.concurrency(default).total == 16
    for bad in ({"total": 0}, {"total": 500}, {"per_resource": 1000}, {"per_account": -1}):
        with pytest.raises(ValidationError):
            ConcurrencyUpdate(**{"total": 8, "per_account": 4, "per_service": 2, "per_resource": 8, **bad})


def test_lease_has_one_holder_until_it_expires():
    state = WebState(make_store(), KST)
    assert state.acquire_lease("a", 60, T)
    assert state.acquire_lease("a", 60, T + timedelta(seconds=30))  # the holder renews
    assert not state.acquire_lease("b", 60, T + timedelta(seconds=40))  # still held
    assert state.acquire_lease("b", 60, T + timedelta(seconds=200))  # expired: takeover
    assert not state.acquire_lease("a", 60, T + timedelta(seconds=210))


# ---------------------------------------------------------------------------------------------- runner
def test_submit_runs_the_services_in_one_scan(env):
    store, _, stub, runner, _ = env
    sub = runner.submit(["sqs", "sns"], {"type": "manual", "by": "alice"}, flags=["--collect-userdata"])
    assert sub.accepted == ["sqs", "sns"] and sub.skipped == {} and sub.scan_id
    assert runner.wait_idle()
    assert stub.calls == [{"services": ["sns", "sqs"], "scan_id": sub.scan_id,
                           "trigger": {"type": "manual", "by": "alice"}, "flags": ["--collect-userdata"]}]
    assert store.coll("scans").find_one({"scan_id": sub.scan_id})["status"] == "COMPLETED"


def test_a_busy_or_unknown_service_is_never_queued_twice(env):
    _, _, stub, runner, _ = env
    stub.gate = threading.Event()
    first = runner.submit(["sqs"], {"type": "manual"})
    assert stub.entered.wait(2)  # sqs is running now
    again = runner.submit(["sqs", "sns", "nope"], {"type": "manual"})
    assert again.accepted == ["sns"] and again.skipped == {"sqs": "이미 실행 중", "nope": "알 수 없거나 꺼져 있는 항목"}
    third = runner.submit(["sns"], {"type": "manual"})
    assert third.scan_id is None and third.skipped == {"sns": "이미 대기 중"}
    assert runner.busy_services() == {"sqs": "running", "sns": "queued"}
    state = runner.state()
    assert state["running"]["scan_id"] == first.scan_id and [q["services"] for q in state["queued"]] == [["sns"]]
    stub.gate.set()
    assert runner.wait_idle()
    assert [c["services"] for c in stub.calls] == [["sqs"], ["sns"]]  # strictly one after the other


def test_akamai_is_a_known_item_only_when_configured(env):
    _, settings, stub, runner, _ = env
    assert runner.submit(["akamai"], {"type": "manual"}).scan_id is None
    settings.akamai = [AkamaiAccountSettings(name="main", env_prefix="X")]
    assert runner.submit(["akamai"], {"type": "manual"}).accepted == ["akamai"]


def test_a_crashing_run_is_recorded_as_failed_and_the_worker_survives(env):
    store, _, stub, runner, _ = env
    stub.fail = RuntimeError("config broke")
    sub = runner.submit(["sqs"], {"type": "manual"})
    assert runner.wait_idle()
    scan = store.coll("scans").find_one({"scan_id": sub.scan_id})
    assert scan["status"] == "FAILED" and "config broke" in scan["summary"]["error"] and scan["finished_at"]
    stub.fail = None
    assert runner.submit(["sns"], {"type": "manual"}).scan_id and runner.wait_idle()
    assert store.coll("scans").count_documents({"status": "COMPLETED"}) == 1


# ---------------------------------------------------------------------------------------------- scheduler
def test_tick_fires_everything_due_in_one_run_and_moves_next_run_forward(env):
    store, _, stub, runner, state = env
    state.set_schedule("sqs", Schedule(kind="minutes", every_minutes=30), True, "u", T)
    state.set_schedule("sns", Schedule(kind="minutes", every_minutes=30), True, "u", T)
    state.set_schedule("kms", Schedule(kind="daily", time="23:00"), True, "u", T)
    sched = Scheduler(state, runner, KST, owner="me")
    assert sched.tick(T + timedelta(minutes=10))["triggered"] == []  # nothing due yet

    res = sched.tick(T + timedelta(minutes=31))
    assert sorted(res["triggered"]) == ["sns", "sqs"] and res["leader"]
    assert runner.wait_idle()
    assert len(stub.calls) == 1 and stub.calls[0]["trigger"] == {"type": "schedule", "by": "scheduler"}
    doc = state.schedules()["sqs"]
    assert doc["last_scan_id"] == res["scan_id"] and doc["last_skip"] is None
    assert doc["next_run"] == naive_utc(datetime(2026, 10, 22, 10, 0, tzinfo=KST))  # 09:31 -> next :00/:30 slot
    assert sched.tick(T + timedelta(minutes=32))["triggered"] == []  # not fired twice for the same slot


def test_a_missed_period_runs_once_not_once_per_missed_period(env):
    _, _, stub, runner, state = env
    state.set_schedule("sqs", Schedule(kind="minutes", every_minutes=5), True, "u", T)
    Scheduler(state, runner, KST, owner="me").tick(T + timedelta(hours=5))  # the server was down for 60 periods
    assert runner.wait_idle() and len(stub.calls) == 1


def test_a_busy_item_is_skipped_and_the_reason_is_kept(env):
    _, _, stub, runner, state = env
    stub.gate = threading.Event()
    runner.submit(["sqs"], {"type": "manual"})
    assert stub.entered.wait(2)
    state.set_schedule("sqs", Schedule(kind="minutes", every_minutes=5), True, "u", T)
    res = Scheduler(state, runner, KST, owner="me").tick(T + timedelta(minutes=6))
    assert res["triggered"] == [] and res["skipped"] == {"sqs": "이미 실행 중"}
    doc = state.schedules()["sqs"]
    assert doc["last_skip"] == "이미 실행 중" and doc["next_run"] > naive_utc(T + timedelta(minutes=6))  # still moves on
    assert any(a["action"] == "skipped" for a in state.recent_audit())
    stub.gate.set()


def test_only_the_lease_holder_fires_schedules(env):
    _, _, stub, runner, state = env
    state.set_schedule("sqs", Schedule(kind="minutes", every_minutes=5), True, "u", T)
    first = Scheduler(state, runner, KST, owner="server-a")
    second = Scheduler(state, runner, KST, owner="server-b")
    now = T + timedelta(minutes=6)
    assert first.tick(now)["leader"] and not second.tick(now)["leader"]
    assert runner.wait_idle() and len(stub.calls) == 1


def test_unknown_items_in_a_schedule_do_not_break_the_tick(env):
    _, _, stub, runner, state = env
    state.set_schedule("service-removed-from-spec", Schedule(kind="minutes", every_minutes=5), True, "u", T)
    res = Scheduler(state, runner, KST, owner="me").tick(T + timedelta(minutes=6))
    assert res["triggered"] == [] and "service-removed-from-spec" in res["skipped"]
    assert state.schedules()["service-removed-from-spec"]["next_run"] is not None  # keeps its rhythm, no crash loop
