"""EdgeGrid HTTP client: token-bucket rate limit, 429/5xx backoff, credentials never logged."""
from __future__ import annotations

import os
import time
from typing import Any, Callable, Protocol
from urllib.parse import urljoin

import requests
from akamai.edgegrid import EdgeGridAuth, EdgeRc

from cspm_collector.core.config import AkamaiAccountSettings
from cspm_collector.core.errors import Status
from cspm_collector.core.ratelimit import TokenBucket

RETRYABLE = {429, 500, 502, 503, 504}


class AkamaiHttpError(Exception):
    """A non-2xx answer (after retries). ``str()`` carries the status and path only: no query, no body,
    because the query may hold the account switch key."""

    def __init__(self, status: int, path: str, code: str | None = None, detail: str | None = None):
        super().__init__(f"HTTP {status} for {path}")
        self.status, self.path, self.code, self.detail = status, path, code, detail  # detail: Akamai's problem text


class AkamaiClient(Protocol):
    def get(self, path: str, params: dict | None = None, headers: dict | None = None) -> dict: ...


def classify_http_error(exc: BaseException) -> Status:
    if isinstance(exc, AkamaiHttpError):
        if exc.status in (401, 403):
            return Status.ACCESS_DENIED
        if exc.status == 429:
            return Status.THROTTLED_GIVEUP
        if exc.status == 400 and "not available" in (exc.detail or "").lower():
            return Status.NOT_SUPPORTED  # e.g. "Feature not available in this product": a fact about the contract, not a failure
        return Status.ERROR
    if isinstance(exc, (requests.Timeout, requests.ConnectionError)):
        return Status.TIMEOUT if isinstance(exc, requests.Timeout) else Status.ERROR
    return Status.ERROR


def _credentials(cfg: AkamaiAccountSettings) -> tuple[str, EdgeGridAuth]:
    """Return ``(base_url, auth)`` from environment variables or an .edgerc section."""
    if cfg.env_prefix:
        names = {k: f"{cfg.env_prefix}_{k.upper()}" for k in ("host", "client_token", "client_secret", "access_token")}
        missing = [n for n in names.values() if not os.environ.get(n)]
        if missing:
            raise RuntimeError(f"missing environment variables: {', '.join(missing)}")
        auth = EdgeGridAuth(os.environ[names["client_token"]], os.environ[names["client_secret"]],
                            os.environ[names["access_token"]])
        return f"https://{os.environ[names['host']]}", auth
    if not cfg.edgerc:
        raise RuntimeError(f"akamai account '{cfg.name}': set edgerc or env_prefix")
    rc = EdgeRc(os.path.expanduser(cfg.edgerc))
    return f"https://{rc.get(cfg.section, 'host')}", EdgeGridAuth.from_edgerc(rc, cfg.section)


class EdgeGridClient:
    def __init__(self, base_url: str, auth: EdgeGridAuth, *, account_switch_key: str | None = None,
                 requests_per_second: float = 1.5, max_retries: int = 6, timeout: tuple[float, float] = (5, 60),
                 session: requests.Session | None = None, sleep: Callable[[float], None] = time.sleep):
        self.base_url = base_url
        self._session = session or requests.Session()
        self._session.auth = auth
        self._switch_key = account_switch_key
        self._bucket = TokenBucket(requests_per_second, burst=max(1, int(requests_per_second * 2)), sleep=sleep)
        self._max_retries, self._timeout, self._sleep = max_retries, timeout, sleep
        self.calls = 0

    @classmethod
    def from_settings(cls, cfg: AkamaiAccountSettings) -> "EdgeGridClient":
        base_url, auth = _credentials(cfg)
        switch = os.environ.get(cfg.account_switch_key_env) if cfg.account_switch_key_env else None
        if cfg.account_switch_key_env and not switch:
            raise RuntimeError(f"env var {cfg.account_switch_key_env} is not set")
        return cls(base_url, auth, account_switch_key=switch, requests_per_second=cfg.requests_per_second,
                   max_retries=cfg.max_retries)

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after and retry_after.isdigit():
            return float(retry_after)
        return 5.0 + 10.0 * attempt  # Akamai's PAPI guidance: a few seconds, growing by 10s per retry

    def get(self, path: str, params: dict | None = None, headers: dict | None = None) -> dict[str, Any]:
        query = dict(params or {})
        if self._switch_key:
            query["accountSwitchKey"] = self._switch_key
        url = urljoin(self.base_url, path)
        for attempt in range(self._max_retries + 1):
            self._bucket.acquire()
            self.calls += 1
            resp = self._session.get(url, params=query, headers=headers, timeout=self._timeout)
            if resp.status_code < 300:
                return resp.json() if resp.content else {}
            if resp.status_code in RETRYABLE and attempt < self._max_retries:
                self._sleep(self._delay(attempt, resp.headers.get("Retry-After")))
                continue
            code = detail = None
            try:
                body = resp.json() or {}
                code, detail = body.get("type"), str(body.get("detail") or "")[:200] or None
            except (ValueError, AttributeError):
                pass
            raise AkamaiHttpError(resp.status_code, path, code, detail)
        raise AssertionError("unreachable")
