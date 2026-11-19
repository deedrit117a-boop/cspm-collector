"""Summaries derived from raw Akamai data. The raw responses are always stored too."""
from __future__ import annotations

EDGE_SUFFIXES = (".edgekey.net", ".edgesuite.net", ".akamaized.net", ".edgekey-staging.net", ".edgesuite-staging.net")


def norm_host(value: str | None) -> str | None:
    """Lower-case, no trailing dot: the form used to match Akamai names against AWS DNS names."""
    return value.strip().rstrip(".").lower() if isinstance(value, str) and value.strip() else None


def unique_hosts(values) -> list[str]:
    seen: dict[str, None] = {}
    for v in values:
        n = norm_host(v)
        if n:
            seen.setdefault(n)
    return list(seen)


def _criteria(rule: dict) -> list[dict]:
    must = rule.get("criteriaMustSatisfy", "all")
    return [{"name": c.get("name"), "options": c.get("options", {}), "must_satisfy": must}
            for c in rule.get("criteria") or []]


def _origin_summary(behavior: dict, path: list[str], criteria: list[dict]) -> dict:
    opts = behavior.get("options") or {}
    host = opts.get("hostname")
    if not host and isinstance(opts.get("netStorage"), dict):  # NetStorage origins name a download domain instead
        host = opts["netStorage"].get("downloadDomainName")
    return {
        "hostname": host,
        "is_variable": isinstance(host, str) and "{{" in host,  # e.g. {{user.PMUSER_ORIGIN}}: resolved at the edge
        "origin_type": opts.get("originType"),
        "http_port": opts.get("httpPort"),
        "https_port": opts.get("httpsPort"),
        "forward_host_header": opts.get("forwardHostHeader"),
        "custom_forward_host_header": opts.get("customForwardHostHeader"),
        "cache_key_hostname": opts.get("cacheKeyHostname"),
        "verification_mode": opts.get("verificationMode"),
        "rule_path": path,
        "criteria": criteria,  # conditions of this rule and of every ancestor: which requests reach this origin
    }


def summarize_origins(rule: dict, path: list[str] | None = None, inherited: list[dict] | None = None) -> list[dict]:
    """Walk a PAPI rule tree and list every ``origin`` behavior with its path and conditions."""
    path = (path or []) + [rule.get("name", "")]
    criteria = (inherited or []) + _criteria(rule)
    found = [_origin_summary(b, path, criteria) for b in rule.get("behaviors") or [] if b.get("name") == "origin"]
    for child in rule.get("children") or []:
        found += summarize_origins(child, path, criteria)
    return found


def origin_hostnames(origins: list[dict]) -> list[str]:
    return unique_hosts(o["hostname"] for o in origins if o.get("hostname") and not o.get("is_variable"))


def is_edge_hostname(name: str | None) -> bool:
    n = norm_host(name)
    return bool(n) and n.endswith(EDGE_SUFFIXES)
