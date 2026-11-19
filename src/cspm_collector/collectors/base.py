"""Collector interface, context and registry."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from cspm_collector.core.ratelimit import TokenBucket
from cspm_collector.core.session import DEFAULT_REGION, AccountSession
from cspm_collector.core.stats import Stats
from cspm_collector.spec.schema import ServiceSpec
from cspm_collector.storage.records import ResourceRecord, StatusRecord


@dataclass(frozen=True)
class CollectOptions:
    flags: frozenset[str] = frozenset()  # opt-in flags such as "--collect-userdata"
    per_resource_workers: int = 8
    poll_interval: float = 2.0  # IAM credential report polling
    poll_timeout: float = 60.0

    def enabled(self, flag: str | None) -> bool:
        return flag is None or flag in self.flags


@dataclass
class CollectContext:
    account: AccountSession
    region: str  # a real region, or "global" for account-wide services
    service: ServiceSpec
    stats: Stats = field(default_factory=Stats)
    options: CollectOptions = field(default_factory=CollectOptions)
    bucket: TokenBucket | None = None
    # resource_type -> {resource_id: {"config", "detail_checked_at"}} of the stored copies, and the oldest "detail_checked_at"
    # that may still be trusted (None / no lookup: every resource is read in full)
    previous: Callable[[str], dict[str, dict]] | None = None
    reuse_since: datetime | None = None

    @property
    def account_id(self) -> str:
        return self.account.account_id

    @property
    def aws_region(self) -> str:
        if self.region == "global":
            return self.service.api_region or DEFAULT_REGION
        return self.region

    def client(self, name: str | None = None, region: str | None = None):
        return self.account.client(name or self.service.client, region or self.aws_region)


@dataclass
class CollectResult:
    resources: list[ResourceRecord] = field(default_factory=list)
    statuses: list[StatusRecord] = field(default_factory=list)
    settings: list[tuple[str, object]] = field(default_factory=list)  # (setting name, value)
    reused: int = 0  # resources whose detail calls were skipped because the stored copy is still current


class Collector(ABC):
    @abstractmethod
    def collect(self, ctx: CollectContext) -> CollectResult: ...


_REGISTRY: dict[str, type[Collector]] = {}


def register(name: str):
    def deco(cls: type[Collector]) -> type[Collector]:
        _REGISTRY[name] = cls
        return cls

    return deco


def get_collector(name: str) -> type[Collector]:
    from . import load_all  # noqa: PLC0415 - imports the modules so they self-register

    load_all()
    if name not in _REGISTRY:
        raise KeyError(f"no collector registered as '{name}'")
    return _REGISTRY[name]


def registered() -> list[str]:
    from . import load_all  # noqa: PLC0415

    load_all()
    return sorted(_REGISTRY)
