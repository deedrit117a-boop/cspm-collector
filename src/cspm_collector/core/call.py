"""Call one AWS API: pagination, app-level backoff, timing, error classification."""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from .errors import Classification, Status, classify_exception, is_throttle
from .ratelimit import TokenBucket
from .stats import Stats

# (response key holding the next token, request parameter to send it in)
_TOKEN_KEYS = (
    ("NextToken", "NextToken"),
    ("nextToken", "nextToken"),
    ("NextMarker", "Marker"),
    ("NextContinuationToken", "ContinuationToken"),
    ("ContinuationToken", "ContinuationToken"),  # s3.list_buckets
    ("nextPageToken", "pageToken"),  # lightsail
)
MAX_PAGES = 10_000


@dataclass
class CallResult:
    status: Status
    pages: list[dict] = field(default_factory=list)
    empty: bool = False  # "no such configuration": SUCCESS, config=None
    error_code: str | None = None
    error_message: str | None = None
    duration_ms: float = 0.0
    api_calls: int = 0

    @property
    def ok(self) -> bool:
        return self.status is Status.SUCCESS


def strip_metadata(resp: dict) -> dict:
    return {k: v for k, v in resp.items() if k != "ResponseMetadata"}


def _with_backoff(fn, *, attempts: int, base: float, sleep):
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - rethrown unless it is a throttle we can retry
            if not is_throttle(exc) or attempt == attempts - 1:
                raise
            sleep(random.uniform(0, base * 2**attempt))  # full jitter


def _input_members(client, api: str) -> set[str]:
    try:
        op = client.meta.method_to_api_mapping[api]
        return set(client.meta.service_model.operation_model(op).input_shape.members)
    except Exception:  # noqa: BLE001 - stand-in clients in tests have no model
        return set()


def _iter_pages(client, api: str, params: dict, paginate: bool):
    if paginate and client.can_paginate(api):
        yield from client.get_paginator(api).paginate(**params)
        return
    params = dict(params)
    accepted = _input_members(client, api)
    for _ in range(MAX_PAGES):
        resp = getattr(client, api)(**params)
        yield resp
        for resp_key, req_key in _TOKEN_KEYS:
            if resp.get(resp_key):
                # most APIs read "Marker" back, but e.g. WAF reads "NextMarker": ask the model
                params[resp_key if resp_key in accepted else req_key] = resp[resp_key]
                break
        else:
            return


def call_api(
    client,
    service: str,
    api: str,
    params: dict | None = None,
    *,
    paginate: bool = True,
    stats: Stats | None = None,
    bucket: TokenBucket | None = None,
    attempts: int = 3,
    backoff_base: float = 1.0,
    sleep=time.sleep,
) -> CallResult:
    """Never raises for AWS/transport errors: they come back as ``CallResult.status``."""
    params = params or {}
    start = time.perf_counter()
    pages: list[dict] = []
    calls = 0
    try:
        def run():
            nonlocal calls
            out = []
            it = _iter_pages(client, api, params, paginate)
            while True:
                if bucket:
                    bucket.acquire()
                try:
                    page = next(it)
                except StopIteration:
                    return out
                calls += 1
                out.append(strip_metadata(page))

        pages = _with_backoff(run, attempts=attempts, base=backoff_base, sleep=sleep)
        result = CallResult(Status.SUCCESS, pages=pages)
    except Exception as exc:  # noqa: BLE001
        c: Classification = classify_exception(exc, service)
        result = CallResult(
            c.status, empty=c.empty, error_code=c.code, error_message=c.message,
        )
        if c.empty:
            result.status = Status.SUCCESS
    result.duration_ms = (time.perf_counter() - start) * 1000
    result.api_calls = max(calls, 1)
    if stats:
        stats.record(service, api, result.duration_ms, error=not result.ok)
    return result
