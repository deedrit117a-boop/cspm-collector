"""Regions an account uses but has not listed: found by the periodic detection and shown on the dashboard."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import mongomock
import pytest

from cspm_collector.core.config import AccountSettings, MongoSettings, Settings
from cspm_collector.core.regions import detect_used_regions
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store
from cspm_collector.web.region_batch import drift
from cspm_collector.web.runner import RunManager
from cspm_collector.web.scheduler import Scheduler
from cspm_collector.web.state import WebState
from test_regions import Client, Sess, wait_done
from test_web_api import UI, make

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
KST = ZoneInfo("Asia/Seoul")
NOW = datetime(2026, 10, 30, 9, 0, tzinfo=KST)


def acct(i, regions):
    return AccountSettings(account_id=i, name=f"a{i}", regions=regions)


def result(ok=True, used=(), at=None):
    return {"ok": ok, "used": list(used), "collect": list(used), "at": at or datetime(2026, 10, 30),
            "detail": [{"region": r, "state": "used", "evidence": ["SQS 큐"]} for r in used]}


def test_drift_lists_used_regions_missing_from_a_fixed_list_only():
    accounts = [acct("1", ["ap-northeast-2"]), acct("2", None), acct("3", ["ap-northeast-2"]), acct("4", ["ap-northeast-2"]),
                acct("5", ["ap-northeast-2"])]
    results = {"1": result(used=["ap-northeast-2", "us-east-1"]),
               "2": result(used=["us-east-1"]),  # no fixed list: every enabled region is collected anyway
               "3": result(ok=False),  # a failed detection is never a change
               "4": result(used=["ap-northeast-2"])}  # nothing new
    out = drift(results, accounts)
    assert list(out) == ["1"] and out["1"]["new"] == ["us-east-1"] and out["1"]["evidence"] == {"us-east-1": ["SQS 큐"]}
    assert out["1"]["name"] == "a1"


def test_overview_shows_the_drift_after_a_detection(monkeypatch):
    client, rt, *_ = make()
    try:
        monkeypatch.setattr("cspm_collector.web.app.detect_regions", lambda account, always: detect_used_regions(
            Sess({"ap-northeast-2": Client({"eni"}), "us-east-1": Client({"sqs"}), "eu-west-1": Client()}), always=always))
        mine = {"account_id": "444455556666", "name": "dev-game", "env": "dev", "regions": ["ap-northeast-2"]}
        assert client.post("/api/accounts", json=mine, headers=UI).status_code == 201
        assert client.get("/api/overview").json()["region_drift"] == {}  # nothing detected yet
        client.post("/api/accounts/regions/detect", json={}, headers=UI)
        wait_done(client)
        o = client.get("/api/overview").json()
        assert o["region_check_days"] == 7
        # 111 lists seoul + virginia (both used): no change; 444455556666 lists only seoul but also uses virginia
        assert list(o["region_drift"]) == ["444455556666"]
        assert o["region_drift"]["444455556666"]["new"] == ["us-east-1"] and o["region_drift"]["444455556666"]["evidence"] == {"us-east-1": ["SQS 큐"]}
    finally:
        rt.stop()


# ----------------------------------------------------------------------------- the periodic check
class FakeBatch:
    def __init__(self):
        self.started = []

    def start(self, ids, user):
        self.started.append((ids, user))
        return {}, True


def scheduler(days=7, batch=None):
    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()
    settings = Settings(accounts=[acct("1", ["ap-northeast-2"])], region_check_days=days)
    runner = RunManager(store, lambda: settings, lambda: load_spec(SPEC), run_fn=lambda *a, **k: None)
    batch = batch if batch is not None else FakeBatch()
    return Scheduler(WebState(store, KST), runner, KST, region_batch=batch), batch


def test_the_detection_starts_when_never_run_and_again_only_after_the_period():
    sch, batch = scheduler(days=7)
    sch.tick(NOW)
    assert batch.started == [(None, "scheduler")]  # never ran: now
    sch.tick(NOW + timedelta(days=3))
    assert len(batch.started) == 1  # not yet
    sch.tick(NOW + timedelta(days=7, minutes=1))
    assert len(batch.started) == 2


def test_the_periodic_detection_can_be_switched_off_and_a_busy_batch_is_not_marked():
    sch, batch = scheduler(days=0)
    sch.tick(NOW)
    assert batch.started == []

    class Busy(FakeBatch):
        def start(self, ids, user):
            self.started.append((ids, user))
            return {}, False  # a batch is already running

    sch, batch = scheduler(days=7, batch=Busy())
    sch.tick(NOW)
    sch.tick(NOW + timedelta(seconds=30))
    assert len(batch.started) == 2  # asked again at the next tick, because nothing was started yet
