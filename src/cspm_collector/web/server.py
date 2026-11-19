"""Wires the control page together: store, state, run queue, scheduler and HTTP app."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from zoneinfo import ZoneInfo

from fastapi import FastAPI

from cspm_collector.core.config import Settings
from cspm_collector.core.scan import run_scan
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store

from .accounts import WebAccounts, merged
from . import app as app_module
from .app import WebDeps, create_app
from .region_batch import RegionDetectRunner
from .checks import CheckRunner, check_account
from .preflight import make_preflight
from . import retention as retention_mod
from .health import collection_health
from .notify import Notifier, default_post
from .runner import RunManager
from .scheduler import Scheduler
from .state import WebState


@dataclass
class Runtime:
    app: FastAPI
    runner: RunManager
    scheduler: Scheduler
    state: WebState

    def start(self) -> None:
        self.runner.start()
        self.scheduler.start()

    def stop(self) -> None:
        self.scheduler.stop()
        self.runner.stop()


def build_runtime(settings: Settings, store: Store, *, spec_path: str | None = None, run_fn: Callable = run_scan,
                  run_kwargs: dict | None = None, token: str | None = None, user_header: str | None = None,
                  allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "[::1]"),
                  tick_seconds: float = 20.0, check_fn: Callable = check_account,
                  profiles_fn: Callable | None = None, preflight_on: bool = False,
                  notify_post: Callable | None = None, org_lister: Callable | None = None) -> Runtime:
    tz = ZoneInfo(settings.timezone)
    spec_path = spec_path or settings.spec_path
    state = WebState(store, tz)

    web_accounts = WebAccounts(store)

    def current_settings() -> Settings:
        """The file's settings plus what was edited on the page (concurrency, accounts); applies from the next run on."""
        return settings.model_copy(update={"concurrency": state.concurrency(settings.concurrency),
                                           "accounts": merged(settings.accounts, web_accounts.list())})

    preflight = make_preflight(store, check_fn, **({"profiles": profiles_fn} if profiles_fn else {})) if preflight_on else None
    def names() -> dict[str, str]:
        cur = current_settings()
        return {**{a.account_id: a.name or a.account_id for a in cur.accounts}, **{f"akamai:{a.name}": f"{a.name} (Akamai)" for a in cur.akamai}}

    notifier = Notifier(store, lambda: settings.notify_webhook_env, names, post=notify_post or default_post,
                        health=lambda: collection_health(store, names(), 10))
    runner = RunManager(store, current_settings, lambda: load_spec(spec_path), run_fn=run_fn, run_kwargs=run_kwargs,
                        preflight=preflight, on_finished=notifier.run_finished)

    def retention_run(now):
        cfg = retention_mod.load(store)
        return retention_mod.purge(store, cfg, now) if cfg.enabled else None
    holder: dict = {}
    region_batch = RegionDetectRunner(store, lambda: current_settings().accounts,
                                      lambda acct, always: (holder["deps"].detector or app_module.detect_regions)(acct, always))
    scheduler = Scheduler(state, runner, tz, tick_seconds=tick_seconds, region_batch=region_batch, retention=retention_run)
    checker = CheckRunner(store, lambda: current_settings().accounts, check=check_fn,
                          **({"profiles": profiles_fn} if profiles_fn else {}))
    deps = WebDeps(settings=settings, store=store, state=state, runner=runner, spec_path=spec_path, tz=tz, checker=checker,
                   token=token, user_header=user_header, allowed_hosts=allowed_hosts, load_settings=current_settings,
                   region_batch=region_batch, notifier=notifier, org_lister=org_lister)
    holder["deps"] = deps
    return Runtime(create_app(deps), runner, scheduler, state)
