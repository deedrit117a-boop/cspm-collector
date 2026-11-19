"""Decide which ``(account, region, service)`` ranges may have disappeared resources swept."""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from cspm_collector.core.errors import Status

from .records import StatusRecord, SweepScope


def derive_scan_status(rows: Iterable[StatusRecord]) -> str:
    """COMPLETED / PARTIAL / FAILED. NOT_ENABLED, NOT_SUPPORTED and SKIPPED are valid outcomes."""
    failures = {Status.ACCESS_DENIED, Status.THROTTLED_GIVEUP, Status.TIMEOUT, Status.ERROR}
    rows = list(rows)
    if not rows or all(r.status in failures for r in rows):
        return "FAILED"
    return "PARTIAL" if any(r.status in failures for r in rows) else "COMPLETED"


def sweepable_scopes(rows: Iterable[StatusRecord]) -> list[SweepScope]:
    """Ranges that were read completely, so resources missing from them are really gone.

    * every API of the scope succeeded        -> sweep all resource types
    * some failed, others (typed) succeeded   -> sweep only types whose APIs all succeeded
    * a failed API without a resource_type    -> sweep nothing in that scope
    """
    by_scope: dict[tuple[str, str, str], list[StatusRecord]] = defaultdict(list)
    for r in rows:
        if r.affects_sweep:  # detail calls only enrich resources that the list API already returned
            by_scope[(r.account_id, r.region, r.service)].append(r)

    scopes: list[SweepScope] = []
    for (account, region, service), group in by_scope.items():
        failed = [r for r in group if r.status is not Status.SUCCESS]
        if not failed:
            scopes.append(SweepScope(account, region, service, None))
            continue
        if any(r.resource_type is None for r in failed):
            continue
        bad = {r.resource_type for r in failed}
        good = {r.resource_type for r in group if r.status is Status.SUCCESS and r.resource_type} - bad
        if good:
            scopes.append(SweepScope(account, region, service, frozenset(good)))
    return scopes
