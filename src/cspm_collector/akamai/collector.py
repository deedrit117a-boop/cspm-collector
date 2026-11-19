"""Akamai collection into ``akamai_raw`` documents: PAPI properties, AppSec, Network Lists, Edge DNS.

Everything that can be matched against AWS (hostnames, edge hostnames, origin hostnames) is also exposed as
normalized top-level arrays so the later graph step can join on them with multikey indexes.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from cspm_collector.collectors.base import CollectResult
from cspm_collector.collectors.generic import _Agg
from cspm_collector.core.call import CallResult
from cspm_collector.core.config import AkamaiAccountSettings
from cspm_collector.core.errors import Status
from cspm_collector.core.stats import Stats
from cspm_collector.storage.records import ResourceRecord, StatusRecord

from .client import AkamaiClient, AkamaiHttpError, classify_http_error
from .rules import is_edge_hostname, norm_host, origin_hostnames, summarize_origins, unique_hosts

SERVICE = "akamai"
PAPI_RULES_ACCEPT = "application/vnd.akamai.papirules.latest+json"
PAGE_SIZE = 1000

# the top-level field(s) each answer must have (one of them is enough). An answer that has other fields but none of
# these means Akamai changed the format: it is recorded as UNEXPECTED_RESPONSE instead of being read as "nothing there"
# (which would also let the sweep soft-delete everything that was collected before).
EXPECTED_FIELDS: dict[str, tuple[str, ...]] = {
    "papi_groups": ("groups",), "papi_contracts": ("contracts",), "papi_properties": ("properties",),
    "appsec_configs": ("configurations",), "appsec_policies": ("policies",), "appsec_match_targets": ("matchTargets",),
    "appsec_ip_geo_firewall": ("block", "ipControls", "geoControls"), "appsec_custom_rules": ("customRules",),
    "network_lists": ("networkLists",),
}

# status row key -> (resource type it enumerates, may a failure block the soft-delete sweep of that type)
ROWS: dict[str, tuple[str | None, bool]] = {
    "papi_groups": ("group", True),
    "papi_contracts": ("contract", True),
    "papi_properties": ("property", True),
    "papi_hostnames": ("property_version", True),
    "papi_rules": ("property_version", True),
    "appsec_configs": ("appsec_config", True),
    "appsec_policies": ("appsec_policy", True),
    "appsec_match_targets": ("appsec_match_target", True),
    "appsec_selected_hostnames": ("appsec_config", False),  # only enriches the config document
    "appsec_ip_geo_firewall": ("appsec_ip_geo_firewall", True),  # which network lists a policy blocks / allows (+ geo)
    "appsec_bypass_network_lists": ("appsec_bypass_network_lists", True),  # lists that bypass the whole configuration
    "appsec_policy_custom_rules": ("appsec_policy_custom_rules", True),  # which custom rules a policy uses, and their actions
    "appsec_custom_rules": ("appsec_custom_rule", True),  # custom rules of a configuration (not versioned)
    "appsec_custom_rule_detail": ("appsec_custom_rule", True),  # one call per rule: its conditions (IPs, network lists)
    "network_lists": ("network_list", True),
    "edgedns_zones": ("dns_zone", True),
    "edgedns_recordsets": ("dns_record", True),
}


class AkamaiCollector:
    def __init__(self, client: AkamaiClient, cfg: AkamaiAccountSettings, stats: Stats | None = None):
        self.client, self.cfg, self.stats = client, cfg, stats
        self.account_id = f"akamai:{cfg.name}"
        self._lock = threading.Lock()
        self._aggs: dict[str, _Agg] = defaultdict(_Agg)
        self._resources: list[ResourceRecord] = []
        self._version_docs = 0

    # ------------------------------------------------------------------ plumbing
    def _get(self, key: str, path: str, params: dict | None = None, headers: dict | None = None) -> dict | None:
        """One API call; failures are recorded under ``key`` and returned as ``None``."""
        start = time.perf_counter()
        try:
            data = self.client.get(path, params, headers)
            res = CallResult(Status.SUCCESS, pages=[data], api_calls=1)
            wanted = EXPECTED_FIELDS.get(key)
            if wanted and isinstance(data, dict) and data and not any(f in data for f in wanted):
                res = CallResult(Status.ERROR, error_code="UNEXPECTED_RESPONSE", api_calls=1,
                                 error_message=f"the answer has none of {list(wanted)}; its fields: {sorted(data)[:8]}")
                data = None
        except Exception as exc:  # noqa: BLE001 - classified, never fatal
            res = CallResult(classify_http_error(exc), error_code=_code(exc), error_message=str(exc), api_calls=1)
            data = None
        res.duration_ms = (time.perf_counter() - start) * 1000
        with self._lock:
            self._aggs[key].add(res)
        if self.stats:
            self.stats.record(SERVICE, key, res.duration_ms, error=not res.ok)
        return data

    def _count(self, key: str, n: int) -> None:
        with self._lock:
            self._aggs[key].count += n

    def _add(self, rtype: str, rid: str, config, arn: str | None = None, extra: dict | None = None) -> None:
        rec = ResourceRecord(self.account_id, "global", SERVICE, rtype, rid, config, arn=arn, extra=extra or {})
        with self._lock:
            self._resources.append(rec)

    def _paged(self, key: str, path: str, list_key: str) -> list[dict] | None:
        """Edge DNS style paging (page / pageSize / metadata.totalElements). ``None`` if any page failed."""
        items: list[dict] = []
        page = 1
        while True:
            data = self._get(key, path, {"page": page, "pageSize": PAGE_SIZE})
            if data is None:
                return None
            batch = data.get(list_key) or []
            items += batch
            total = (data.get("metadata") or {}).get("totalElements", len(items))
            if not batch or len(items) >= total:
                return items
            page += 1

    # ------------------------------------------------------------------ main
    def collect(self) -> CollectResult:
        cfg = self.cfg.collect
        with ThreadPoolExecutor(max_workers=self.cfg.max_workers, thread_name_prefix="akamai") as pool:
            self._pool = pool
            if cfg.properties:
                self._papi()
            if cfg.appsec:
                self._appsec()
            if cfg.network_lists:
                self._network_lists()
            if cfg.edge_dns:
                self._edge_dns()
        return CollectResult(resources=self._resources, statuses=self._statuses())

    def _statuses(self) -> list[StatusRecord]:
        rows: list[StatusRecord] = []
        for key, agg in self._aggs.items():
            rtype, sweeps = ROWS.get(key, (None, False))
            code, msg = agg.first_error
            if agg.status() is not Status.SUCCESS and agg.calls > 1:
                msg = f"{sum(agg.failures.values())}/{agg.calls} calls failed; first: {msg}"
            rows.append(StatusRecord(self.account_id, "global", SERVICE, key, agg.status(), resource_type=rtype,
                                     resource_count=agg.count, error_code=code, error=msg,
                                     duration_ms=agg.duration_ms, api_calls=agg.api_calls, affects_sweep=sweeps))
        listing = self._aggs.get("papi_properties")
        if listing is not None:  # version documents exist only if the property listing was complete
            rows.append(StatusRecord(self.account_id, "global", SERVICE, "papi_property_versions", listing.status(),
                                     resource_type="property_version", resource_count=self._version_docs,
                                     error_code=listing.first_error[0], error=listing.first_error[1]))
        return rows

    def _pmap(self, fn, items):
        def safe(x):
            try:
                return fn(x)
            except Exception as exc:  # noqa: BLE001 - a bug on one item must not stop the account
                with self._lock:
                    agg = self._aggs["_internal"]
                    agg.failures[Status.ERROR] += 1
                    agg.first_error = (type(exc).__name__, str(exc))
                return None

        return list(self._pool.map(safe, items))

    # ------------------------------------------------------------------ PAPI
    def _papi(self) -> None:
        groups = ((self._get("papi_groups", "/papi/v1/groups") or {}).get("groups") or {}).get("items") or []
        for g in groups:
            self._add("group", g["groupId"], g)
        self._count("papi_groups", len(groups))

        contracts = ((self._get("papi_contracts", "/papi/v1/contracts") or {}).get("contracts") or {}).get("items") or []
        for c in contracts:
            self._add("contract", c["contractId"], c)
        self._count("papi_contracts", len(contracts))

        pairs = sorted({(c, g["groupId"]) for g in groups for c in g.get("contractIds") or []})
        listed = self._pmap(lambda p: self._list_properties(*p), pairs)
        props: dict[str, dict] = {}
        for items in listed:
            for it in items or []:
                props.setdefault(it["propertyId"], it)
        self._count("papi_properties", len(props))
        for p in props.values():
            self._add("property", p["propertyId"], p)

        # one fetch per distinct (property, version); a version active on both networks yields two documents
        wanted: dict[tuple[str, int], dict] = {}
        for p in props.values():
            for net, field in (("PRODUCTION", "productionVersion"), ("STAGING", "stagingVersion")):
                if p.get(field):
                    wanted.setdefault((p["propertyId"], p[field]), p)
        fetched = dict(zip(wanted, self._pmap(lambda k: self._fetch_version(wanted[k], k[1]), list(wanted))))
        for p in props.values():
            for net, field in (("PRODUCTION", "productionVersion"), ("STAGING", "stagingVersion")):
                data = fetched.get((p["propertyId"], p.get(field)))
                if p.get(field) and data:
                    self._add_version(p, net, p[field], *data)

    def _list_properties(self, contract_id: str, group_id: str) -> list[dict] | None:
        data = self._get("papi_properties", "/papi/v1/properties", {"contractId": contract_id, "groupId": group_id})
        return None if data is None else (data.get("properties") or {}).get("items") or []

    def _fetch_version(self, prop: dict, version: int):
        base = f"/papi/v1/properties/{prop['propertyId']}/versions/{version}"
        ids = {"contractId": prop.get("contractId"), "groupId": prop.get("groupId")}
        hostnames = self._get("papi_hostnames", f"{base}/hostnames", ids)
        rules = self._get("papi_rules", f"{base}/rules", {**ids, "validateRules": "false"},
                          {"Accept": PAPI_RULES_ACCEPT})
        if hostnames is None or rules is None:
            return None
        return hostnames, rules

    def _add_version(self, prop: dict, network: str, version: int, hostnames: dict, rules: dict) -> None:
        items = (hostnames.get("hostnames") or {}).get("items") or []
        origins = summarize_origins(rules.get("rules") or {})
        config = {"property": prop, "network": network, "version": version, "hostnames": hostnames, "rules": rules}
        extra = {
            "property_id": prop["propertyId"], "property_name": prop.get("propertyName"), "version": version,
            "network": network, "group_id": prop.get("groupId"), "contract_id": prop.get("contractId"),
            "hostnames": unique_hosts(i.get("cnameFrom") for i in items),
            "edge_hostnames": unique_hosts(i.get("cnameTo") for i in items),
            "origin_hostnames": origin_hostnames(origins), "origins": origins,
            "rule_format": rules.get("ruleFormat"), "etag": rules.get("etag"),
        }
        self._add("property_version", f"{prop['propertyId']}|{network}", config, extra=extra)
        with self._lock:
            self._version_docs += 1
            self._aggs["papi_hostnames"].count += 1
            self._aggs["papi_rules"].count += 1

    # ------------------------------------------------------------------ AppSec
    def _appsec(self) -> None:
        configs = (self._get("appsec_configs", "/appsec/v1/configs") or {}).get("configurations") or []
        self._count("appsec_configs", len(configs))
        self._pmap(self._appsec_config, configs)

    @staticmethod
    def _appsec_version(cfg: dict) -> tuple[int | None, str]:
        for field, source in (("productionVersion", "production"), ("stagingVersion", "staging"),
                              ("latestVersion", "latest")):
            if cfg.get(field):
                return cfg[field], source
        return None, "none"

    def _appsec_config(self, cfg: dict) -> None:
        cid, (version, source) = cfg["id"], self._appsec_version(cfg)
        meta = {"config_id": cid, "config_name": cfg.get("name"), "version": version, "version_source": source}
        details: dict = {}
        hostnames: list[str] = []
        if version is not None:
            base = f"/appsec/v1/configs/{cid}/versions/{version}"
            policies = (self._get("appsec_policies", f"{base}/security-policies") or {}).get("policies") or []
            for p in policies:
                self._add("appsec_policy", f"{cid}|{p['policyId']}", p,
                          extra={**meta, "policy_id": p["policyId"]})
            self._count("appsec_policies", len(policies))

            # which network lists each policy uses, and for what (block / allow / geo)
            for p in policies:
                fw = self._get("appsec_ip_geo_firewall", f"{base}/security-policies/{p['policyId']}/ip-geo-firewall")
                if fw is not None:
                    self._add("appsec_ip_geo_firewall", f"{cid}|{p['policyId']}", fw, extra={**meta, "policy_id": p["policyId"]})
                    self._count("appsec_ip_geo_firewall", 1)

            for p in policies:  # the custom rules a policy uses (rule id, name, action): who blocks / allows what
                used = self._get("appsec_policy_custom_rules", f"{base}/security-policies/{p['policyId']}/custom-rules")
                if used is not None:
                    self._add("appsec_policy_custom_rules", f"{cid}|{p['policyId']}", {"customRules": used},
                              extra={**meta, "policy_id": p["policyId"]})
                    self._count("appsec_policy_custom_rules", 1)

            # network lists that bypass the whole configuration (one document per configuration)
            bypass = self._get("appsec_bypass_network_lists", f"{base}/bypass-network-lists")
            if bypass is not None:
                self._add("appsec_bypass_network_lists", str(cid), bypass, extra=dict(meta))
                self._count("appsec_bypass_network_lists", 1)

            data = (self._get("appsec_match_targets", f"{base}/match-targets") or {}).get("matchTargets") or {}
            targets = [t for kind in ("websiteTargets", "apiTargets") for t in data.get(kind) or []]
            for t in targets:
                self._add("appsec_match_target", f"{cid}|{t['targetId']}", t, extra={
                    **meta, "policy_id": (t.get("securityPolicy") or {}).get("policyId"),
                    "hostnames": unique_hosts(t.get("hostnames") or [])})
            self._count("appsec_match_targets", len(targets))

            selected = self._get("appsec_selected_hostnames", f"{base}/selected-hostnames")
            if selected is not None:
                details["selected_hostnames"] = selected
                hostnames = unique_hosts(h.get("hostname") for h in selected.get("hostnameList") or [])
        config = {**cfg, "_details": details} if details else dict(cfg)
        self._add("appsec_config", str(cid), config, extra={**meta, "hostnames": hostnames})
        self._custom_rules(cid, cfg.get("name"))

    def _custom_rules(self, cid, name) -> None:
        """Custom rules belong to the configuration, not to a version: the list holds only id / name / status, the
        conditions (IPs, network lists) come with one call per rule."""
        listed = self._get("appsec_custom_rules", f"/appsec/v1/configs/{cid}/custom-rules")
        rules = [r for r in (listed or {}).get("customRules") or [] if str(r.get("status", "")).lower() != "deleted"]
        self._count("appsec_custom_rules", len(rules))
        for r in rules:
            detail = self._get("appsec_custom_rule_detail", f"/appsec/v1/configs/{cid}/custom-rules/{r['id']}")
            if detail is not None:
                self._add("appsec_custom_rule", f"{cid}|{r['id']}", detail,
                          extra={"config_id": cid, "config_name": name, "rule_id": r["id"], "rule_version": r.get("version"),
                                 "rule_status": r.get("status")})

    # ------------------------------------------------------------------ Network Lists / Edge DNS
    def _network_lists(self) -> None:
        data = self._get("network_lists", "/network-list/v2/network-lists", {"includeElements": "true"})
        lists = (data or {}).get("networkLists") or []
        for nl in lists:
            self._add("network_list", nl["uniqueId"], nl)
        self._count("network_lists", len(lists))

    def _edge_dns(self) -> None:
        zones = self._paged("edgedns_zones", "/config-dns/v2/zones", "zones")
        for z in zones or []:
            self._add("dns_zone", z["zone"], z)
        self._count("edgedns_zones", len(zones or []))
        self._pmap(self._zone_records, [z["zone"] for z in zones or []])

    def _zone_records(self, zone: str) -> None:
        records = self._paged("edgedns_recordsets", f"/config-dns/v2/zones/{zone}/recordsets", "recordsets")
        for r in records or []:
            rdata = r.get("rdata") or []
            self._add("dns_record", f"{zone}|{r['name']}|{r['type']}", r, extra={
                "zone": zone, "hostnames": unique_hosts([r["name"]]),
                "edge_hostnames": unique_hosts(v for v in rdata if is_edge_hostname(v))})
        self._count("edgedns_recordsets", len(records or []))


def _code(exc: BaseException) -> str:
    return f"HTTP{exc.status}" if isinstance(exc, AkamaiHttpError) else type(exc).__name__
