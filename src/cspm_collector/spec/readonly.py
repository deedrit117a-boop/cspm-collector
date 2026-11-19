"""Read-only guard: only lookup-style AWS API names may appear in a spec."""
from __future__ import annotations

import re

ALLOWED_PREFIXES = ("describe_", "list_", "get_", "batch_get_")
ALLOWED_EXACT = frozenset({"generate_credential_report"})

# Not matching the prefixes above but known to be read-only. Each is expensive or
# starts a server-side report, so specs must gate them behind ``opt_in_flag``.
OPT_IN_ONLY = frozenset(
    {
        "head_bucket",
        "lookup_events",
        "filter_log_events",
        "search_tables",
        "generate_service_last_accessed_details",
    }
)

_MUTATING = re.compile(
    r"^(create|delete|put|update|modify|remove|attach|detach|start|stop|terminate|"
    r"run|reboot|set|enable|disable|associate|disassociate|tag|untag|register|"
    r"deregister|revoke|authorize|invoke|publish|send|reset|restore|copy|import|"
    r"upload|add|apply|cancel|change|replace|rotate|schedule|accept|reject)_"
)


def check_api_name(api: str, opt_in_flag: str | None) -> tuple[str, str] | None:
    """Return ``("error"|"warning", message)`` or ``None`` if the name is fine."""
    if api in ALLOWED_EXACT or api.startswith(ALLOWED_PREFIXES):
        return None
    if api in OPT_IN_ONLY:
        if opt_in_flag:
            return None
        return ("error", f"{api} is read-only but must declare opt_in_flag")
    if _MUTATING.match(api):
        return ("error", f"{api} looks like a mutating API")
    return ("warning", f"{api} is not a describe_/list_/get_/batch_get_ API")
