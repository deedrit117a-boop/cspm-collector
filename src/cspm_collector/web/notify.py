"""Tell people when a collection needs attention, without anyone having to open the page.

A message is a small JSON ``{"text": ...}`` posted to a webhook (Slack, Teams and most chat tools accept that shape). The webhook
URL is a secret: it is read from an **environment variable of the server** (its name is ``notify_webhook_env`` in the settings,
``CSPM_NOTIFY_WEBHOOK`` by default) and is never stored in the database, shown on the page or written to a log.

Off until someone turns it on (page: settings > notifications). A message is sent
* when a run ended PARTIAL / FAILED (not while an automatic retry of it is still waiting: the retry's end is reported instead), or
  accounts were left out by the pre-run check,
* when the collection health shows a warning that was not there at the last message (consecutive failures, slower, fewer resources),
* when the response shape of an AWS item changed (a field disappeared or appeared).
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Callable

import structlog
from pydantic import BaseModel, ConfigDict

from cspm_collector.storage.records import now_utc
from cspm_collector.storage.store import Store

log = structlog.get_logger("cspm.notify")
TIMEOUT_SECONDS = 10


class NotifySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    on_failure: bool = True  # a run that ended PARTIAL / FAILED, or left accounts out
    on_warning: bool = True  # a new warning of the collection health
    on_shape: bool = True  # an AWS answer changed its fields
    on_completed: bool = False  # also every run that went fine (noisy: for a while after turning it on)


def default_post(url: str, text: str) -> None:
    import requests

    r = requests.post(url, json={"text": text}, timeout=TIMEOUT_SECONDS)
    r.raise_for_status()


class Notifier:
    def __init__(self, store: Store, webhook_env: Callable[[], str], names: Callable[[], dict[str, str]],
                 post: Callable[[str, str], None] = default_post, health: Callable[[], dict] | None = None):
        self.store, self._env, self._names, self._post, self._health = store, webhook_env, names, post, health

    # ------------------------------------------------------------------ settings
    def settings(self) -> NotifySettings:
        doc = self.store.coll("settings").find_one({"_id": "notify"}) or {}
        return NotifySettings(**{k: doc[k] for k in NotifySettings.model_fields if k in doc})

    def save(self, values: NotifySettings, user: str, now: datetime) -> NotifySettings:
        self.store.coll("settings").update_one({"_id": "notify"}, {"$set": {**values.model_dump(), "updated_by": user,
                                                                            "updated_at": now.replace(tzinfo=None)}}, upsert=True)
        return values

    def view(self) -> dict:
        env = self._env()
        return {**self.settings().model_dump(), "webhook_env": env, "webhook_configured": bool(os.environ.get(env))}

    # ------------------------------------------------------------------ sending
    def send(self, text: str) -> tuple[bool, str]:
        """Post one message. Never raises; the URL never appears in the answer."""
        url = os.environ.get(self._env())
        if not url:
            return False, f"서버에 환경변수 {self._env()}가 설정되어 있지 않습니다"
        try:
            self._post(url, text)
        except Exception as exc:  # noqa: BLE001
            log.error("notification failed", error=type(exc).__name__)
            return False, f"전송하지 못했습니다 ({type(exc).__name__})"
        return True, "보냈습니다"

    def test(self) -> tuple[bool, str]:
        return self.send("[CSPM 수집기] 알림 연결 테스트입니다.")

    # ------------------------------------------------------------------ what to say
    def run_finished(self, scan_id: str, will_retry: bool = False) -> None:
        """Called by the run queue when a run ended. Everything here is best effort."""
        try:
            cfg = self.settings()
            if not cfg.enabled or not os.environ.get(self._env()):
                return
            scan = self.store.coll("scans").find_one({"scan_id": scan_id})
            if not scan or scan["status"] == "CANCELLED":
                return
            lines = []
            left_out = (scan.get("options") or {}).get("preflight_excluded") or []
            bad = scan["status"] in ("PARTIAL", "FAILED") or bool(left_out)
            if cfg.on_failure and bad and not will_retry:
                lines.append(self._run_line(scan, left_out))
            elif cfg.on_completed and not bad:
                lines.append(self._run_line(scan, left_out))
            if cfg.on_shape:
                for c in ((scan.get("summary") or {}).get("shape_changes") or [])[:5]:
                    gone = ", ".join(c["removed"][:4]) or "-"
                    new = ", ".join(c["added"][:4]) or "-"
                    lines.append(f"응답 형식 변화 {c['service']}/{c['resource_type']}: 없어진 필드 {gone} · 새 필드 {new}")
            if cfg.on_warning and not will_retry:
                lines += self._new_warnings()
            if lines:
                self.send("[CSPM 수집기]\n" + "\n".join(lines))
        except Exception as exc:  # noqa: BLE001 - a notification must never hurt the collection
            log.error("notification skipped", error=type(exc).__name__)

    def _run_line(self, scan: dict, left_out: list[str]) -> str:
        names = self._names()
        summ = scan.get("summary") or {}
        res = summ.get("resources") or {}
        total = sum(res.get(k, 0) for k in ("inserted", "updated", "unchanged"))
        bad = [names.get(a, a) for a, d in self.store.scan_accounts(scan["scan_id"]).items() if d.get("status") not in ("COMPLETED", None)]
        parts = [f"수집 {scan['status']} · {total:,}건"]
        if bad:
            parts.append("문제 어카운트 " + ", ".join(bad[:8]) + (f" 외 {len(bad) - 8}개" if len(bad) > 8 else ""))
        if left_out:
            parts.append(f"사전 점검에서 제외 {len(left_out)}개")
        return " · ".join(parts) + f" ({scan['scan_id']})"

    def _new_warnings(self) -> list[str]:
        if self._health is None:
            return []
        names = self._names()
        found = {(a["account_id"], w["type"], w.get("service", "")): f"{names.get(a['account_id'], a['account_id'])}: {w['message']}"
                 for a in self._health().get("accounts", []) for w in a["warnings"]}
        coll = self.store.coll("runtime")
        known = set(map(tuple, (coll.find_one({"_id": "notify_state"}) or {}).get("warnings") or []))
        coll.update_one({"_id": "notify_state"}, {"$set": {"warnings": sorted(map(list, found)), "at": now_utc()}}, upsert=True)
        fresh = [text for key, text in found.items() if key not in known]
        return [f"주의 {t}" for t in fresh[:8]] + ([f"주의 외 {len(fresh) - 8}건"] if len(fresh) > 8 else [])
