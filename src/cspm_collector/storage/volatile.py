"""Fields that change without the configuration changing.

Two kinds of noise were seen in real accounts and would flood ``resource_history`` if they counted as changes:

* **volatile**: telemetry that moves whenever a resource is *used* (an IAM role's ``RoleLastUsed``, a user's last
  login, access-key last-used). They are left out of the change hash, but their stored value is still refreshed on
  every scan (without a history entry), so "last used" data in the database stays current.
* **unordered lists**: lists AWS returns in a different order from call to call (a route table's
  ``Associations``). They are compared as sets.

Both tables are keyed by ``(service, resource_type)`` and hold dotted paths into the stored ``config``. They only
influence the hash; the stored ``config`` is always the unmodified API response.
"""
from __future__ import annotations

import copy
import json
from typing import Any

VOLATILE: dict[tuple[str, str], list[str]] = {
    ("iam", "role"): ["_details.get_role.Role.RoleLastUsed"],
    ("iam", "user"): ["PasswordLastUsed", "_details.get_user.User.PasswordLastUsed", "_details.get_access_key_last_used"],
    # RDS-family clusters/instances: the point-in-time-recovery window moves every few minutes
    ("rds", "db_cluster"): ["LatestRestorableTime", "EarliestRestorableTime", "EarliestBacktrackTime"],
    ("rds", "db_instance"): ["LatestRestorableTime"],
    ("documentdb", "db_cluster"): ["LatestRestorableTime", "EarliestRestorableTime"],
    ("documentdb", "db_instance"): ["LatestRestorableTime"],
    ("neptune", "db_cluster"): ["LatestRestorableTime", "EarliestRestorableTime"],
    ("neptune", "db_instance"): ["LatestRestorableTime"],
    # SSM agents ping every few minutes and associations run on schedules
    ("ssm", "managed_instance"): ["LastPingDateTime", "LastAssociationExecutionDate", "LastSuccessfulAssociationExecutionDate"],
    # Trusted Advisor results are re-evaluated continuously and different calls return different cached snapshots
    # (timestamps even go backwards, flagged resources and counts flip): derived findings, not configuration. The
    # latest result is always stored, but never counts as a change of the check itself.
    ("trustedadvisor", "check"): ["_details.describe_trusted_advisor_check_result"],
    ("iam", "credential_report_row"): [
        "password_last_used", "_generated_time",
        "access_key_1_last_used_date", "access_key_1_last_used_region", "access_key_1_last_used_service",
        "access_key_2_last_used_date", "access_key_2_last_used_region", "access_key_2_last_used_service",
    ],
}

UNORDERED: dict[tuple[str, str], list[str]] = {
    ("vpc", "route_table"): ["Associations"],
}

_MISSING = object()


def volatile_paths(service: str, rtype: str) -> list[str]:
    return VOLATILE.get((service, rtype), [])


def dig(obj: Any, path: str) -> Any:
    """Value at a dotted path, or ``_MISSING``."""
    for part in path.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return _MISSING
        obj = obj[part]
    return obj


def _drop(obj: dict, path: str) -> None:
    *parents, last = path.split(".")
    for part in parents:
        obj = obj.get(part) if isinstance(obj, dict) else None
        if not isinstance(obj, dict):
            return
    obj.pop(last, None)


def _sort_list(obj: dict, path: str) -> None:
    *parents, last = path.split(".")
    for part in parents:
        obj = obj.get(part) if isinstance(obj, dict) else None
        if not isinstance(obj, dict):
            return
    if isinstance(obj.get(last), list):
        obj[last] = sorted(obj[last], key=lambda v: json.dumps(v, sort_keys=True, default=str))


def stable_view(service: str, rtype: str, config: Any) -> Any:
    """``config`` as the change hash should see it: volatile fields removed, unordered lists sorted."""
    drop, unordered = VOLATILE.get((service, rtype)), UNORDERED.get((service, rtype))
    if not (drop or unordered) or not isinstance(config, dict):
        return config
    view = copy.deepcopy(config)
    for path in drop or ():
        _drop(view, path)
    for path in unordered or ():
        _sort_list(view, path)
    return view


def volatile_values(service: str, rtype: str, config: Any) -> dict[str, Any]:
    """The current value of every volatile path present in ``config`` (to refresh the stored copy)."""
    found = {}
    for path in volatile_paths(service, rtype):
        value = dig(config, path)
        if value is not _MISSING:
            found[path] = value
    return found
