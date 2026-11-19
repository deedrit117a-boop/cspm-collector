"""The check before a run: unusable accounts are left out with the reason, the others are collected."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
import mongomock
from moto import mock_aws

from cspm_collector.core.config import AccountSettings, ConcurrencySettings, MongoSettings, Settings
from cspm_collector.core.scan import ScanFilter, run_scan
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store
from cspm_collector.web.preflight import make_preflight
from cspm_collector.web.runner import RunManager

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
R = "ap-northeast-2"
TRIG = {"type": "manual", "by": "t"}


def store_():
    s = Store(mongomock.MongoClient()["d"], MongoSettings())
    s.init_db()
    return s


def accounts(*ids):
    return [AccountSettings(account_id=i, name=f"a{i}", regions=[R]) for i in ids]


# ----------------------------------------------------------------------------- make_preflight
def test_preflight_reports_only_the_failed_accounts_and_stores_every_result():
    store = store_()
    seen = []

    def check(acct, profiles):
        seen.append(acct.account_id)
        ok = acct.account_id != "2"
        return {"account_id": acct.account_id, "ok": ok, "code": "OK" if ok else "SSO_LOGIN_NEEDED",
                "message": "" if ok else "SSO login needed", "hint": "" if ok else "aws sso login", "at": datetime.now(timezone.utc).replace(tzinfo=None)}

    pre = make_preflight(store, check, profiles=lambda: set())
    failed = pre(accounts("1", "2", "3"))
    assert failed == {"2": {"code": "SSO_LOGIN_NEEDED", "message": "SSO login needed", "hint": "aws sso login"}}
    stored = store.coll("runtime").find_one({"_id": "account_checks"})["results"]
    assert set(stored) == {"1", "2", "3"} and stored["2"]["ok"] is False  # the accounts page shows the same result
    seen.clear()
    assert pre(accounts("1", "2", "3")).keys() == {"2"} and sorted(seen) == ["2"]  # fresh good results are trusted


def test_preflight_turns_a_crashing_check_into_a_failed_account():
    def boom(acct, profiles):
        raise RuntimeError("env var CSPM_EXTID_X is not set")

    failed = make_preflight(store_(), boom, profiles=lambda: set())(
        [AccountSettings(account_id="1", role_arn="arn:aws:iam::000000000001:role/X", external_id_env="CSPM_EXTID_X")])
    assert failed["1"]["code"] == "EXTERNAL_ID_ENV_MISSING"


# ----------------------------------------------------------------------------- in a scan
def test_excluded_accounts_are_not_opened_and_are_listed_with_the_reason():
    with mock_aws():
        settings = Settings(accounts=accounts("123456789012", "999999999999"),
                            concurrency=ConcurrencySettings(total=2, per_account=2, per_service=2))
        boto3.client("sqs", region_name=R).create_queue(QueueName="q1")
        opened = []
        real = __import__("cspm_collector.core.session", fromlist=["AccountSession"]).AccountSession

        def factory(acct):
            opened.append(acct.account_id)
            return real(acct)

        store = store_()
        why = {"999999999999": {"code": "SSO_LOGIN_NEEDED", "message": "SSO login needed.", "hint": "Run aws sso login."}}
        s = run_scan(settings, load_spec(SPEC), store, flt=ScanFilter(services={"sqs"}), session_factory=factory, excluded=why)
        assert opened == ["123456789012"] and s.status == "PARTIAL"
        scan = store.coll("scans").find_one({"scan_id": s.scan_id})
        assert scan["options"]["preflight_excluded"] == ["999999999999"]
        per = store.scan_accounts(s.scan_id)
        assert per["999999999999"]["status"] == "FAILED" and per["999999999999"]["tasks"] == 0
        assert "SSO_LOGIN_NEEDED" in per["999999999999"]["error"] and "aws sso login" in per["999999999999"]["error"]
        assert per["123456789012"]["resources"] == 1


# ----------------------------------------------------------------------------- in the runner
class Capture:
    def __init__(self):
        self.excluded = []

    def __call__(self, settings, spec, store, *, flt, options, scan_id, trigger, excluded=None, **kw):
        self.excluded.append((sorted(flt.services), excluded))
        store.create_scan(scan_id, [], "v", None, {"trigger": trigger})
        store.finish_scan(scan_id, "COMPLETED", {})


def runner_with(pre, **settings_kw):
    settings = Settings(accounts=accounts("1", "2"), **settings_kw)
    cap = Capture()
    runner = RunManager(store_(), lambda: settings, lambda: load_spec(SPEC), run_fn=cap, preflight=pre)
    runner.start()
    return runner, cap


def test_runner_hands_the_failed_accounts_to_the_scan():
    asked = []

    def pre(accts):
        asked.append([a.account_id for a in accts])
        return {"2": {"code": "SSO_LOGIN_NEEDED", "message": "m", "hint": "h"}}

    runner, cap = runner_with(pre)
    try:
        runner.submit(["sqs"], TRIG)
        assert runner.wait_idle(5)
        assert asked == [["1", "2"]] and cap.excluded == [(["sqs"], {"2": {"code": "SSO_LOGIN_NEEDED", "message": "m", "hint": "h"}})]
        runner.submit(["sns"], TRIG, accounts=["1"])
        assert runner.wait_idle(5) and asked[-1] == ["1"]  # only the accounts of the run are checked
    finally:
        runner.stop()


def test_no_check_for_an_akamai_only_run_when_switched_off_or_when_the_check_itself_breaks():
    calls = []
    runner, cap = runner_with(lambda a: calls.append(1) or {})
    try:
        runner.submit(["akamai"], TRIG)  # not a known service here: nothing runs, nothing is checked
        assert calls == []
    finally:
        runner.stop()
    runner, cap = runner_with(lambda a: calls.append(1) or {}, preflight_check=False)
    try:
        runner.submit(["sqs"], TRIG)
        assert runner.wait_idle(5) and calls == [] and cap.excluded == [(["sqs"], {})]
    finally:
        runner.stop()

    def broken(accts):
        raise RuntimeError("check crashed")

    runner, cap = runner_with(broken)
    try:
        runner.submit(["sqs"], TRIG)
        assert runner.wait_idle(5) and cap.excluded == [(["sqs"], {})]  # the run goes on without the check
    finally:
        runner.stop()
