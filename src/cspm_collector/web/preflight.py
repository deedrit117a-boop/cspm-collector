"""The check before a run: accounts that cannot be opened are left out of it, with the reason, instead of failing one by one.

It is the connection check of the accounts page (``checks.check_account``: credentials, role, identity) run for the accounts
of the run, side by side. The newest result of every account is also written to the page's connection column. A result
younger than ``FRESH_SECONDS`` that was fine is trusted, so that several runs in a row do not repeat the checks.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Callable

from cspm_collector.core.config import AccountSettings
from cspm_collector.storage.store import Store

from .accounts import available_profiles
from .checks import CHECK_WORKERS, LABELS, check_account, classify

FRESH_SECONDS = 120


def make_preflight(store: Store, check: Callable[..., dict] = check_account, profiles: Callable[[], set[str]] = available_profiles,
                   workers: int = CHECK_WORKERS) -> Callable[[list[AccountSettings]], dict[str, dict]]:
    def run(accounts: list[AccountSettings]) -> dict[str, dict]:
        """``{account_id: {"code", "message", "hint"}}`` for the accounts that failed (empty: all fine)."""
        coll = store.coll("runtime")
        known = (coll.find_one({"_id": "account_checks"}) or {}).get("results") or {}
        fresh_after = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=FRESH_SECONDS)

        def is_fresh_ok(acct: AccountSettings) -> bool:
            r = known.get(acct.account_id) or {}
            return bool(r.get("ok")) and r.get("at") is not None and r["at"] > fresh_after

        todo = [a for a in accounts if not is_fresh_ok(a)]
        have = profiles()
        failed: dict[str, dict] = {}

        def one(acct: AccountSettings) -> None:
            try:
                res = check(acct, have)
            except Exception as exc:  # noqa: BLE001 - a broken check is a failed account, not a broken run
                code, message, hint = classify(exc, acct)
                res = {"account_id": acct.account_id, "name": acct.name, "ok": False, "code": code, "message": message,
                       "hint": hint, "label": LABELS.get(code, code), "at": datetime.now(timezone.utc).replace(tzinfo=None)}
            coll.update_one({"_id": "account_checks"}, {"$set": {f"results.{acct.account_id}": res}}, upsert=True)
            if not res.get("ok"):
                failed[acct.account_id] = {"code": res.get("code", "ERROR"), "message": res.get("message", ""),
                                           "hint": res.get("hint", "")}

        if todo:
            with ThreadPoolExecutor(max_workers=max(1, min(workers, len(todo)))) as pool:
                list(pool.map(one, todo))
        return failed

    return run
