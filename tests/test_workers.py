import threading
import time

from cspm_collector.core.config import ConcurrencySettings
from cspm_collector.core.workers import Task, run_tasks


def test_failure_isolated_and_all_results_returned():
    tasks = [Task("a", "r", f"s{i}") for i in range(6)]

    def fn(t):
        if t.service == "s3":
            raise ValueError("boom")
        return t.service

    seen = []
    res = run_tasks(tasks, fn, ConcurrencySettings(total=3, per_account=3, per_service=1), on_result=seen.append)
    assert len(res) == 6 and len(seen) == 6
    errs = [r for r in res if r.error]
    assert len(errs) == 1 and isinstance(errs[0].error, ValueError)


def test_limits_respected():
    lock = threading.Lock()
    cur = {"total": 0, "acct": {}, "svc": {}}
    peak = {"total": 0, "acct": 0, "svc": 0}

    def fn(t):
        with lock:
            cur["total"] += 1
            cur["acct"][t.account_id] = cur["acct"].get(t.account_id, 0) + 1
            cur["svc"][t.service] = cur["svc"].get(t.service, 0) + 1
            peak["total"] = max(peak["total"], cur["total"])
            peak["acct"] = max(peak["acct"], max(cur["acct"].values()))
            peak["svc"] = max(peak["svc"], max(cur["svc"].values()))
        time.sleep(0.02)
        with lock:
            cur["total"] -= 1
            cur["acct"][t.account_id] -= 1
            cur["svc"][t.service] -= 1

    tasks = [Task(a, f"r{i}", s) for a in "ab" for s in ("x", "y") for i in range(4)]
    run_tasks(tasks, fn, ConcurrencySettings(total=4, per_account=2, per_service=3))
    assert peak["total"] <= 4 and peak["acct"] <= 2 and peak["svc"] <= 3


def test_busy_account_does_not_block_others():
    order = []
    tasks = [Task("a", "r", f"s{i}") for i in range(4)] + [Task("b", "r", "z")]

    def fn(t):
        order.append(t.account_id)
        time.sleep(0.02)

    run_tasks(tasks, fn, ConcurrencySettings(total=2, per_account=1, per_service=2))
    assert order.index("b") < 3  # not queued behind all of account a
