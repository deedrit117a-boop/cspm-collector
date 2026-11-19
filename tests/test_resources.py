"""Advice on the amount of work from this machine's CPU and memory, and splitting a big run into batches."""
import pytest

from cspm_collector.core.config import ConcurrencySettings
from cspm_collector.core.resources import HostResources, host_resources, observed_rate_per_slot, recommend
from test_web_api import UI, make

CUR = ConcurrencySettings(total=16, per_account=8, per_service=4, per_resource=8)


def host(cpus=16, avail=13000, busy=10.0):
    return HostResources(cpus, 32000, avail, busy)


def test_the_machine_can_be_read_without_error():
    h = host_resources(sample_seconds=0.05)
    assert h.cpus >= 1 and (h.mem_available_mb is None or h.mem_available_mb > 0)
    assert h.cpu_busy_pct is None or 0 <= h.cpu_busy_pct <= 100


def test_a_strong_idle_machine_keeps_the_settings_and_never_advises_above_them():
    r = recommend(300, 10, CUR, host())
    assert r["recommended"] == CUR.model_dump() and r["changed"] is False and r["level"] == "ok" and r["batches"] == 1
    assert recommend(300, 10, ConcurrencySettings(total=4, per_account=2, per_service=2, per_resource=4), host())["recommended"]["total"] == 4


def test_little_memory_lowers_the_concurrency_and_explains_why():
    r = recommend(2000, 40, CUR, host(avail=1200))  # (1200 x 0.6 - 400) / 50 = 6 tasks at once
    rec = r["recommended"]
    assert rec["total"] == 6 and rec["per_account"] == 3 and rec["per_service"] == 4 and r["low_memory"] is False
    assert any("가용 메모리" in x and "6개" in x for x in r["reasons"]) and r["changed"] is True
    assert recommend(2000, 40, CUR, host(avail=800))["low_memory"] is True


def test_a_busy_cpu_and_few_cores_lower_it_too():
    assert recommend(100, 5, CUR, host(cpus=2))["recommended"]["total"] == 12  # 2 cores x 6
    busy = recommend(100, 5, CUR, host(busy=90.0))["recommended"]["total"]
    mid = recommend(100, 5, CUR, host(busy=70.0))["recommended"]["total"]
    assert busy == 8 and mid == 12  # half / three quarters of the 16 that were set
    assert any("이미 90%" in x for x in recommend(100, 5, CUR, host(busy=90.0))["reasons"])


def test_detail_threads_are_kept_in_proportion_to_the_cores():
    r = recommend(100, 5, CUR, host(cpus=1))["recommended"]
    assert r["total"] == 6 and r["per_resource"] == 5  # 6 tasks x 5 detail threads = 30 <= 1 core x 32


def test_a_run_bigger_than_the_machine_holds_is_split_by_accounts():
    r = recommend(2700, 71, CUR, host())  # a run should hold at most 16 x 100 = 1600 tasks
    assert r["tasks_per_run"] == 1600 and r["batches"] == 2 and r["accounts_per_batch"] == 42 and r["level"] == "split"
    small = recommend(2700, 71, CUR, host(cpus=2))  # 12 slots: 1200 tasks per run
    assert small["batches"] == 3 and small["accounts_per_batch"] * small["batches"] >= 71
    assert recommend(5000, 1, CUR, host())["batches"] == 1  # one account cannot be split


def test_the_time_comes_from_earlier_runs_when_there_are_some():
    assert observed_rate_per_slot([]) is None and observed_rate_per_slot([(10, 100.0, 16)]) is None  # too small to say anything
    rate = observed_rate_per_slot([(1600, 100.0, 16), (800, 100.0, 16), (3200, 100.0, 16)])  # 1 task/s per slot (median)
    assert rate == pytest.approx(1.0)
    seen = recommend(1600, 10, CUR, host(), rate_per_slot=rate)
    assert seen["estimated_seconds"] == 100 and seen["estimate_from_history"] is True
    assumed = recommend(1600, 10, CUR, host())
    assert assumed["estimated_seconds"] == 250 and assumed["estimate_from_history"] is False  # 2.5 s a task, 16 at once


# ----------------------------------------------------------------------------- the endpoints
@pytest.fixture
def web():
    client, rt, stub, store = make(more_accounts=True)
    yield client, rt, stub
    rt.stop()


def test_estimate_endpoint_gives_the_size_and_the_advice(web, monkeypatch):
    client, rt, _ = web
    from cspm_collector.web import app as web_app
    monkeypatch.setattr(web_app, "BIG_RUN_TASKS", 2)
    monkeypatch.setattr(web_app, "host_resources", lambda: host(avail=1200))
    r = client.post("/api/runs/estimate", json={"services": ["ec2", "ecs"]}, headers=UI).json()
    assert r["tasks"] == 8 and r["accounts"] == 3 and r["big"] is True  # 2 items x (2 + 1 + 1) regions
    assert r["advice"]["recommended"]["total"] == 6 and r["advice"]["changed"] is True
    assert client.post("/api/runs/estimate", json={"services": ["nope"], "item_groups": ["missing"]}, headers=UI).status_code == 422


def test_the_confirmation_carries_the_advice(web, monkeypatch):
    client, *_ = web
    from cspm_collector.web import app as web_app
    monkeypatch.setattr(web_app, "BIG_RUN_TASKS", 2)
    monkeypatch.setattr(web_app, "host_resources", lambda: host())
    d = client.post("/api/runs", json={"services": ["ec2", "ecs", "rds"]}, headers=UI).json()["detail"]
    assert d["code"] == "CONFIRM_NEEDED" and d["advice"]["recommended"] == d["advice"]["current"]  # an idle strong machine: keep the settings


def test_batch_size_splits_the_accounts_into_queued_runs_with_akamai_only_in_the_first():
    client, rt, stub, _ = make(more_accounts=True, akamai=True)
    try:
        r = client.post("/api/runs", json={"services": ["sqs", "akamai"], "batch_size": 2}, headers=UI)
        assert r.status_code == 202 and r.json()["batches"] == 2 and len(r.json()["scan_ids"]) == 2
        assert rt.runner.wait_idle(10)
        calls = sorted(stub.calls, key=lambda c: c["services"])
        assert [c["services"] for c in calls] == [["akamai", "sqs"], ["sqs"]]
        assert calls[0]["accounts"] == ["111", "222", "main"]  # the first run: two accounts, and Akamai (its own accounts)
        assert calls[1]["accounts"] == ["333"]  # the second: the last one (3 accounts in runs of 2 and 1)
        marks = sorted(c["trigger"]["batch"]["n"] for c in calls)  # the runs of one request carry "batch n of m" and one shared id
        assert marks == [1, 2] and {c["trigger"]["batch"]["of"] for c in calls} == {2} and len({c["trigger"]["batch"]["id"] for c in calls}) == 1
        assert client.post("/api/runs", json={"services": ["sqs"], "batch_size": 0}, headers=UI).status_code == 422
    finally:
        rt.stop()
