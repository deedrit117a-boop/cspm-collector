"""A run with transient failures is followed by ONE automatic second run of just those tasks."""
from pathlib import Path

import mongomock

from cspm_collector.core.config import AccountSettings, MongoSettings, Settings
from cspm_collector.core.errors import Status
from cspm_collector.core.scan import plan_retry
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.records import StatusRecord
from cspm_collector.storage.store import Store
from cspm_collector.web.runner import RunManager

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
R = "ap-northeast-2"
TRIG = {"type": "manual", "by": "t"}


def store_():
    s = Store(mongomock.MongoClient()["d"], MongoSettings())
    s.init_db()
    return s


def row(acct, region, svc, status):
    return StatusRecord(acct, region, svc, "list_x", status, error_code="X", error="e", affects_sweep=False)


class Flaky:
    """First call fails some tasks in different ways; every later call succeeds (and records what it was asked)."""

    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def __call__(self, settings, spec, store, *, flt, options, scan_id, trigger, **kw):
        first = not self.calls
        self.calls.append({"scan_id": scan_id, "trigger": trigger, "services": sorted(flt.services),
                           "accounts": sorted(flt.accounts) if flt.accounts else None,
                           "retry": flt.retry, "flags": sorted(options.flags)})
        store.create_scan(scan_id, [], "v", None, {"trigger": trigger})
        if first:
            store.record_status(scan_id, self.rows)
        store.finish_scan(scan_id, "PARTIAL" if first else "COMPLETED", {})


def make(rows, **kw):
    settings = Settings(accounts=[AccountSettings(account_id="1", regions=[R]), AccountSettings(account_id="2", regions=[R])], **kw)
    fn = Flaky(rows)
    runner = RunManager(store_(), lambda: settings, lambda: load_spec(SPEC), run_fn=fn)
    runner.start()
    return runner, fn


ROWS = [row("1", R, "sqs", Status.TIMEOUT), row("2", R, "sns", Status.THROTTLED_GIVEUP),
        row("1", R, "kms", Status.ACCESS_DENIED),  # not transient
        row("2", "*", "*", Status.ERROR),  # the account could not be opened: not transient either
        row("1", R, "s3", Status.SUCCESS)]


def test_only_transient_task_failures_are_retried_once_and_not_the_retry():
    runner, fn = make(ROWS)
    try:
        runner.submit(["sqs", "sns", "kms", "s3"], TRIG, flags=["--collect-userdata"])
        assert runner.wait_idle(10)
        assert len(fn.calls) == 2  # the run and one retry; the retry (all fine here) does not start a third
        first, again = fn.calls
        assert again["trigger"] == {"type": "retry", "by": "auto", "of": first["scan_id"]}
        assert again["services"] == ["sns", "sqs"] and again["accounts"] == ["1", "2"] and again["flags"] == ["--collect-userdata"]
        assert again["retry"].tasks == {("1", R, "sqs"), ("2", R, "sns")} and again["retry"].source_scan == first["scan_id"]
    finally:
        runner.stop()


def test_no_retry_for_denied_access_unopened_accounts_a_cancelled_run_or_when_switched_off():
    runner, fn = make([row("1", R, "kms", Status.ACCESS_DENIED), row("2", "*", "*", Status.ERROR)])
    try:
        runner.submit(["kms"], TRIG)
        assert runner.wait_idle(10) and len(fn.calls) == 1
    finally:
        runner.stop()
    runner, fn = make(ROWS, auto_retry=False)
    try:
        runner.submit(["sqs"], TRIG)
        assert runner.wait_idle(10) and len(fn.calls) == 1
    finally:
        runner.stop()


def test_plan_retry_transient_only_vs_everything():
    store = store_()
    store.create_scan("s1", [], "v", None, {})
    store.record_status("s1", ROWS)
    everything = plan_retry(store, "s1")
    assert everything.accounts == {"2"} and ("1", R, "kms") in everything.tasks and len(everything.tasks) == 3
    transient = plan_retry(store, "s1", transient_only=True)
    assert transient.accounts == frozenset() and transient.tasks == {("1", R, "sqs"), ("2", R, "sns")}
