"""Plain data carriers between collectors and the store."""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cspm_collector.core.errors import Status


def new_scan_id() -> str:
    return f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"


def resource_key(account_id: str, region: str, service: str, resource_type: str, resource_id: str) -> str:
    """Deterministic ``_id`` of a resource document."""
    raw = "|".join((account_id, region, service, resource_type, resource_id))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


@dataclass
class ResourceRecord:
    account_id: str
    region: str  # "global" for global services
    service: str
    resource_type: str
    resource_id: str
    config: Any  # raw API response fragment
    arn: str | None = None
    tags: dict | list | None = None  # {"k": "v"} or [{"Key": .., "Value": ..}]
    extra: dict = field(default_factory=dict)  # e.g. {"secret_findings": [...]}

    @property
    def key(self) -> str:
        return resource_key(self.account_id, self.region, self.service, self.resource_type, self.resource_id)


@dataclass
class StatusRecord:
    account_id: str
    region: str
    service: str
    api: str
    status: Status
    resource_type: str | None = None
    resource_count: int = 0
    error_code: str | None = None
    error: str | None = None
    duration_ms: float = 0.0
    api_calls: int = 0
    affects_sweep: bool = True  # False for per-resource detail calls and account settings


@dataclass
class SaveStats:
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    history: int = 0
    chunked: int = 0

    def add(self, other: "SaveStats") -> None:
        for name in ("inserted", "updated", "unchanged", "history", "chunked"):
            setattr(self, name, getattr(self, name) + getattr(other, name))


@dataclass(frozen=True)
class SweepScope:
    account_id: str
    region: str
    service: str
    resource_types: frozenset[str] | None = None  # None = every resource type


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
