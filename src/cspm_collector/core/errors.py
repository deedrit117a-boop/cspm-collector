"""Map exceptions to a ``collection_status`` value using ``error_map.yaml``."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from importlib import resources

import yaml
from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)


class Status(str, Enum):
    SUCCESS = "SUCCESS"
    ACCESS_DENIED = "ACCESS_DENIED"
    NOT_ENABLED = "NOT_ENABLED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    THROTTLED_GIVEUP = "THROTTLED_GIVEUP"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class Classification:
    status: Status
    empty: bool = False  # "no such configuration": SUCCESS with config=None
    code: str | None = None
    message: str | None = None


_TABLES = {
    "not_enabled": Status.NOT_ENABLED,
    "not_supported": Status.NOT_SUPPORTED,
    "access_denied": Status.ACCESS_DENIED,
    "throttled": Status.THROTTLED_GIVEUP,
}


@lru_cache(maxsize=1)
def load_error_map() -> dict:
    text = resources.files("cspm_collector.core").joinpath("error_map.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


def _lookup(code: str, service: str | None) -> Classification | None:
    emap = load_error_map()
    override = (emap.get("service_overrides") or {}).get(service or "", {}).get(code)
    if override:
        if override == "empty":
            return Classification(Status.SUCCESS, empty=True, code=code)
        return Classification(Status(override), code=code)
    if code in (emap.get("empty") or ()):
        return Classification(Status.SUCCESS, empty=True, code=code)
    for table, status in _TABLES.items():
        if code in (emap.get(table) or ()):
            return Classification(status, code=code)
    return None


def _message_override(code: str, message: str, service: str | None) -> Classification | None:
    """Some services reuse a generic code for "not enabled" and only the message tells them apart."""
    for rule in load_error_map().get("message_overrides") or ():
        if rule["code"] == code and rule["service"] == service and rule["contains"].lower() in message.lower():
            return Classification(Status(rule["status"]), code=code)
    return None


def classify_exception(exc: BaseException, service: str | None = None) -> Classification:
    """Classify an exception raised by a boto3 call."""
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = err.get("Code") or "Unknown"
        found = _message_override(code, err.get("Message") or "", service) or _lookup(code, service)
        if found:
            return Classification(found.status, found.empty, code, err.get("Message"))
        return Classification(Status.ERROR, code=code, message=err.get("Message"))
    if isinstance(exc, (ReadTimeoutError, ConnectTimeoutError)):
        return Classification(Status.TIMEOUT, code=type(exc).__name__, message=str(exc))
    if isinstance(exc, EndpointConnectionError):  # service has no endpoint in this region
        return Classification(Status.NOT_SUPPORTED, code=type(exc).__name__, message=str(exc))
    return Classification(Status.ERROR, code=type(exc).__name__, message=str(exc))


def is_throttle(exc: BaseException) -> bool:
    return isinstance(exc, ClientError) and (
        exc.response.get("Error", {}).get("Code") in (load_error_map().get("throttled") or ())
    )
