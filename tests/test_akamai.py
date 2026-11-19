import copy

import mongomock
import pytest

from cspm_collector.akamai.client import AkamaiHttpError
from cspm_collector.akamai.collector import AkamaiCollector
from cspm_collector.akamai.rules import (
    is_edge_hostname,
    norm_host,
    origin_hostnames,
    summarize_origins,
    unique_hosts,
)
from cspm_collector.core.config import AkamaiAccountSettings, AkamaiCollect, MongoSettings, Settings
from cspm_collector.core.errors import Status
from cspm_collector.core.scan import ScanFilter, run_scan
from cspm_collector.spec.schema import CollectSpec
from cspm_collector.storage.store import Store

RULES_P1 = {
    "accountId": "act_1", "propertyId": "prp_1", "ruleFormat": "v2024-01-09", "etag": "etag-p1",
    "rules": {
        "name": "default",
        "behaviors": [{"name": "origin", "options": {
            "originType": "CUSTOMER", "hostname": "Origin.Example.com.", "httpPort": 80, "httpsPort": 443,
            "forwardHostHeader": "REQUEST_HOST_HEADER", "verificationMode": "PLATFORM_SETTINGS"}}],
        "children": [
            {"name": "API", "criteriaMustSatisfy": "all",
             "criteria": [{"name": "path", "options": {"matchOperator": "MATCHES_ONE_OF", "values": ["/api/*"]}}],
             "behaviors": [{"name": "origin", "options": {"originType": "CUSTOMER", "hostname": "alb-1.elb.amazonaws.com",
                                                           "forwardHostHeader": "ORIGIN_HOSTNAME"}}],
             "children": []},
            {"name": "Dynamic", "criteria": [], "children": [],
             "behaviors": [{"name": "origin", "options": {"originType": "CUSTOMER", "hostname": "{{user.PMUSER_ORIGIN}}"}}]},
            {"name": "Static", "criteria": [], "children": [],
             "behaviors": [{"name": "origin", "options": {"originType": "NET_STORAGE",
                                                           "netStorage": {"downloadDomainName": "x.download.akamai.com"}}}]},
        ],
    },
}


def papi_tree(etag="etag-p1"):
    rules = copy.deepcopy(RULES_P1)
    rules["etag"] = etag
    return rules


class FakeAkamai:
    """Canned PAPI / AppSec / Network List / Edge DNS answers keyed by path."""

    def __init__(self, fail: set[str] | None = None, properties=None, etag="etag-p1", no_bypass=False):
        self.no_bypass = no_bypass
        self.calls: list[tuple[str, dict, dict]] = []
        self.fail = fail or set()
        self.properties = properties if properties is not None else [
            {"propertyId": "prp_1", "propertyName": "www", "contractId": "ctr_1", "groupId": "grp_1",
             "productionVersion": 3, "stagingVersion": 4, "latestVersion": 4},
            {"propertyId": "prp_2", "propertyName": "unused", "contractId": "ctr_1", "groupId": "grp_1",
             "productionVersion": None, "stagingVersion": None, "latestVersion": 1},
            {"propertyId": "prp_3", "propertyName": "same", "contractId": "ctr_1", "groupId": "grp_1",
             "productionVersion": 1, "stagingVersion": 1, "latestVersion": 1},
        ]
        self.etag = etag

    def get(self, path, params=None, headers=None):
        self.calls.append((path, params or {}, headers or {}))
        if any(f in path for f in self.fail):
            raise AkamaiHttpError(500, path)
        if path == "/papi/v1/groups":
            return {"groups": {"items": [{"groupId": "grp_1", "groupName": "Main", "contractIds": ["ctr_1"]}]}}
        if path == "/papi/v1/contracts":
            return {"contracts": {"items": [{"contractId": "ctr_1", "contractTypeName": "Direct"}]}}
        if path == "/papi/v1/properties":
            assert params == {"contractId": "ctr_1", "groupId": "grp_1"}
            return {"properties": {"items": copy.deepcopy(self.properties)}}
        if path.endswith("/hostnames"):
            return {"hostnames": {"items": [
                {"cnameType": "EDGE_HOSTNAME", "cnameFrom": "WWW.Example.com.", "cnameTo": "www.example.com.edgekey.net"},
                {"cnameType": "EDGE_HOSTNAME", "cnameFrom": "img.example.com", "cnameTo": "www.example.com.edgekey.net"}]}}
        if "/rules" in path:
            return papi_tree(self.etag)
        if path == "/appsec/v1/configs":
            return {"configurations": [{"id": 111, "name": "WAF", "latestVersion": 6, "productionVersion": 5},
                                       {"id": 222, "name": "Draft", "latestVersion": 2}]}
        if path.endswith("/security-policies"):
            return {"policies": [{"policyId": "pol1", "policyName": "Default"}]}
        if path.endswith("/match-targets"):
            return {"matchTargets": {"websiteTargets": [
                {"targetId": 1, "type": "website", "hostnames": ["WWW.example.com"], "securityPolicy": {"policyId": "pol1"}}],
                "apiTargets": []}}
        if path.endswith("/ip-geo-firewall"):
            return {"block": "blockSpecificIPGeo", "ipControls": {"blockedIPNetworkLists": {"networkList": ["1_BLOCK"]},
                                                                  "allowedIPNetworkLists": {"networkList": []}},
                    "geoControls": {"blockedIPNetworkLists": {"networkList": []}}}
        if path.endswith("/bypass-network-lists"):
            if self.no_bypass:
                raise AkamaiHttpError(400, path, "INVALID-INPUT-ERROR", "Feature not available in this product")
            return {"networkLists": [{"id": "2_BYPASS", "name": "bypass"}]}
        if "/security-policies/" in path and path.endswith("/custom-rules"):  # a policy's rules: a list with the actions
            return [{"ruleId": 70001, "name": "deny-ip", "action": "deny", "isDeleted": False}]
        if path.endswith("/custom-rules"):  # per configuration (no version in the path), list = id / name / status only
            assert "/versions/" not in path
            return {"customRules": [{"id": 70001, "name": "deny-ip", "status": "used", "version": 3},
                                    {"id": 70002, "name": "old", "status": "deleted", "version": 1}]}
        if "/custom-rules/" in path:
            return {"id": int(path.rsplit("/", 1)[1]), "name": "deny-ip", "conditions": [{"type": "networkListMatch", "value": ["1_BLOCK"]}]}
        if path.endswith("/selected-hostnames"):
            return {"hostnameList": [{"hostname": "www.example.com"}, {"hostname": "Img.example.com."}]}
        if path == "/network-list/v2/network-lists":
            assert params == {"includeElements": "true"}
            return {"networkLists": [{"uniqueId": "1_BLOCK", "name": "block", "type": "IP", "list": ["10.0.0.0/8"]}]}
        if path == "/config-dns/v2/zones":
            return {"zones": [{"zone": "example.com", "type": "PRIMARY"}], "metadata": {"totalElements": 1}}
        if path == "/config-dns/v2/zones/example.com/recordsets":
            return {"recordsets": [
                {"name": "www.example.com", "type": "CNAME", "ttl": 300, "rdata": ["www.example.com.edgekey.net."]},
                {"name": "api.example.com", "type": "A", "ttl": 60, "rdata": ["1.2.3.4"]}], "metadata": {"totalElements": 2}}
        raise AssertionError(f"unexpected path {path}")


def cfg(**collect):
    return AkamaiAccountSettings(name="main", max_workers=2, collect=AkamaiCollect(**collect))


def docs(result, rtype):
    return [r for r in result.resources if r.resource_type == rtype]


# --------------------------------------------------------------------------- summaries
def test_normalization_helpers():
    assert norm_host(" WWW.Example.COM. ") == "www.example.com" and norm_host("") is None and norm_host(None) is None
    assert unique_hosts(["A.com.", "a.com", None, "b.com"]) == ["a.com", "b.com"]
    assert is_edge_hostname("www.example.com.edgekey.net.") and is_edge_hostname("x.edgesuite.net")
    assert not is_edge_hostname("alb-1.elb.amazonaws.com")


def test_origin_summary_paths_conditions_variables_and_netstorage():
    origins = summarize_origins(RULES_P1["rules"])
    assert [o["hostname"] for o in origins] == [
        "Origin.Example.com.", "alb-1.elb.amazonaws.com", "{{user.PMUSER_ORIGIN}}", "x.download.akamai.com"]
    default, api, dynamic, static = origins
    assert default["rule_path"] == ["default"] and default["criteria"] == []
    assert default["https_port"] == 443 and default["forward_host_header"] == "REQUEST_HOST_HEADER"
    assert api["rule_path"] == ["default", "API"] and api["forward_host_header"] == "ORIGIN_HOSTNAME"
    assert api["criteria"] == [{"name": "path", "must_satisfy": "all",
                                "options": {"matchOperator": "MATCHES_ONE_OF", "values": ["/api/*"]}}]
    assert dynamic["is_variable"] and not api["is_variable"]
    assert static["origin_type"] == "NET_STORAGE"
    assert origin_hostnames(origins) == ["origin.example.com", "alb-1.elb.amazonaws.com", "x.download.akamai.com"]


# --------------------------------------------------------------------------- PAPI
def test_papi_documents_and_join_keys():
    fake = FakeAkamai()
    res = AkamaiCollector(fake, cfg(appsec=False, network_lists=False)).collect()
    assert {r.resource_id for r in docs(res, "group")} == {"grp_1"} and docs(res, "contract")[0].resource_id == "ctr_1"
    assert {r.resource_id for r in docs(res, "property")} == {"prp_1", "prp_2", "prp_3"}

    versions = {r.resource_id: r for r in docs(res, "property_version")}
    assert set(versions) == {"prp_1|PRODUCTION", "prp_1|STAGING", "prp_3|PRODUCTION", "prp_3|STAGING"}  # prp_2: nothing active
    prod = versions["prp_1|PRODUCTION"]
    assert prod.extra["version"] == 3 and versions["prp_1|STAGING"].extra["version"] == 4
    assert prod.extra["hostnames"] == ["www.example.com", "img.example.com"]  # normalized join keys
    assert prod.extra["edge_hostnames"] == ["www.example.com.edgekey.net"]
    assert prod.extra["origin_hostnames"] == ["origin.example.com", "alb-1.elb.amazonaws.com", "x.download.akamai.com"]
    assert prod.extra["rule_format"] == "v2024-01-09" and prod.extra["etag"] == "etag-p1"
    assert prod.config["rules"]["rules"] == RULES_P1["rules"]  # the full rule tree is kept raw
    assert prod.config["hostnames"]["hostnames"]["items"][0]["cnameFrom"] == "WWW.Example.com."  # raw, not normalized
    assert prod.account_id == "akamai:main" and prod.region == "global" and prod.service == "akamai"


def test_version_active_on_both_networks_is_fetched_once():
    fake = FakeAkamai()
    AkamaiCollector(fake, cfg(appsec=False, network_lists=False)).collect()
    p3 = [c for c in fake.calls if c[0].startswith("/papi/v1/properties/prp_3/")]
    assert len(p3) == 2  # hostnames + rules, once, although the version is on PRODUCTION and STAGING


def test_rule_tree_requests_use_papi_rules_media_type_and_skip_validation():
    fake = FakeAkamai()
    AkamaiCollector(fake, cfg(appsec=False, network_lists=False)).collect()
    path, params, headers = next(c for c in fake.calls if c[0].endswith("/versions/3/rules"))
    assert headers["Accept"] == "application/vnd.akamai.papirules.latest+json"
    assert params == {"contractId": "ctr_1", "groupId": "grp_1", "validateRules": "false"}


def test_statuses_record_success_counts_and_sweep_types():
    res = AkamaiCollector(FakeAkamai(), cfg()).collect()
    rows = {s.api: s for s in res.statuses}
    assert all(s.status is Status.SUCCESS for s in res.statuses)
    assert rows["papi_properties"].resource_count == 3 and rows["papi_properties"].resource_type == "property"
    assert rows["papi_property_versions"].resource_type == "property_version" and rows["papi_property_versions"].resource_count == 4
    assert rows["appsec_selected_hostnames"].affects_sweep is False
    assert "edgedns_zones" not in rows  # off by default


def test_failed_rule_fetch_yields_no_document_and_a_sweep_blocking_row():
    res = AkamaiCollector(FakeAkamai(fail={"/prp_1/versions/3/rules"}), cfg(appsec=False, network_lists=False)).collect()
    ids = {r.resource_id for r in docs(res, "property_version")}
    assert "prp_1|PRODUCTION" not in ids and "prp_1|STAGING" in ids and "prp_3|PRODUCTION" in ids
    row = next(s for s in res.statuses if s.api == "papi_rules")
    assert row.status is Status.ERROR and row.resource_type == "property_version" and row.affects_sweep
    assert "1/" in row.error  # "1/N calls failed"


# --------------------------------------------------------------------------- AppSec / lists / DNS
def test_appsec_uses_production_then_latest_and_exposes_hostnames():
    res = AkamaiCollector(FakeAkamai(), cfg(properties=False, network_lists=False)).collect()
    cfgs = {r.resource_id: r for r in docs(res, "appsec_config")}
    assert cfgs["111"].extra["version"] == 5 and cfgs["111"].extra["version_source"] == "production"
    assert cfgs["222"].extra["version"] == 2 and cfgs["222"].extra["version_source"] == "latest"
    assert cfgs["111"].extra["hostnames"] == ["www.example.com", "img.example.com"]
    assert "selected_hostnames" in cfgs["111"].config["_details"]
    assert docs(res, "appsec_policy")[0].resource_id.startswith("111|pol1")
    target = docs(res, "appsec_match_target")[0]
    assert target.extra["hostnames"] == ["www.example.com"] and target.extra["policy_id"] == "pol1"


def test_network_lists_and_edge_dns_when_enabled():
    res = AkamaiCollector(FakeAkamai(), cfg(properties=False, appsec=False, edge_dns=True)).collect()
    assert docs(res, "network_list")[0].config["list"] == ["10.0.0.0/8"]
    zone = docs(res, "dns_zone")[0]
    assert zone.resource_id == "example.com"
    recs = {r.resource_id: r for r in docs(res, "dns_record")}
    assert recs["example.com|www.example.com|CNAME"].extra["edge_hostnames"] == ["www.example.com.edgekey.net"]
    assert recs["example.com|api.example.com|A"].extra["edge_hostnames"] == []


def test_edge_dns_pages_until_total(monkeypatch):
    from cspm_collector.akamai import collector as mod

    monkeypatch.setattr(mod, "PAGE_SIZE", 2)

    class Paged(FakeAkamai):
        def get(self, path, params=None, headers=None):
            if path == "/config-dns/v2/zones":
                page = params["page"]
                self.calls.append((path, params, {}))
                return {"zones": [{"zone": f"z{page}a.com"}, {"zone": f"z{page}b.com"}][: 2 if page < 2 else 1],
                        "metadata": {"totalElements": 3}}
            return {"recordsets": [], "metadata": {"totalElements": 0}}

    fake = Paged()
    res = AkamaiCollector(fake, cfg(properties=False, appsec=False, network_lists=False, edge_dns=True)).collect()
    assert len(docs(res, "dns_zone")) == 3 and [c[1]["page"] for c in fake.calls] == [1, 2]


# --------------------------------------------------------------------------- scan integration
@pytest.fixture
def env():
    settings = Settings(akamai=[cfg()])
    spec = CollectSpec(spec_version="t", services=[])
    return settings, spec, Store(mongomock.MongoClient()["cspm"], MongoSettings())


def akamai_scan(env, fake, **kw):
    settings, spec, store = env
    return run_scan(settings, spec, store, flt=ScanFilter(services={"akamai"}),
                    akamai_client_factory=lambda acct: fake, **kw)


def test_scan_stores_akamai_documents_with_multikey_join_keys(env):
    store = env[2]
    s = akamai_scan(env, FakeAkamai())
    assert s.status == "COMPLETED" and s.akamai_resources.inserted > 0
    assert store.db.resources.count_documents({}) == 0  # AWS collection untouched
    hits = list(store.db.akamai_raw.find({"hostnames": "www.example.com", "resource_type": "property_version"}))
    # the fake serves the same hostnames for every property, so all four version documents match
    assert {h["resource_id"] for h in hits} == {"prp_1|PRODUCTION", "prp_1|STAGING", "prp_3|PRODUCTION", "prp_3|STAGING"}
    assert store.db.akamai_raw.count_documents({"origin_hostnames": "alb-1.elb.amazonaws.com"}) == 4
    assert store.db.akamai_raw.count_documents({"edge_hostnames": "www.example.com.edgekey.net"}) == 4
    assert store.db.scans.find_one({"scan_id": s.scan_id})["accounts"] == ["akamai:main"]
    assert store.db.collection_status.count_documents({"scan_id": s.scan_id, "service": "akamai"}) >= 9


def test_second_scan_unchanged_then_change_history_and_sweep(env):
    store = env[2]
    first = akamai_scan(env, FakeAkamai())
    same = akamai_scan(env, FakeAkamai())
    assert (same.akamai_resources.inserted, same.akamai_resources.updated) == (0, 0)
    assert same.akamai_resources.unchanged == first.akamai_resources.inserted

    changed = akamai_scan(env, FakeAkamai(etag="etag-new"))
    assert changed.akamai_resources.updated >= 4 and changed.akamai_resources.history == changed.akamai_resources.updated
    assert store.db.resource_history.count_documents({"resource_type": "property_version"}) >= 4

    gone = FakeAkamai(properties=[p for p in FakeAkamai().properties if p["propertyId"] != "prp_3"])
    akamai_scan(env, gone)
    p3 = store.db.akamai_raw.find_one({"resource_id": "prp_3|PRODUCTION"})
    assert p3["deleted_at"] is not None and store.db.akamai_raw.find_one({"resource_id": "prp_1|PRODUCTION"}).get("deleted_at") is None


def test_failed_listing_never_deletes_akamai_documents(env):
    store = env[2]
    akamai_scan(env, FakeAkamai())

    class Broken(FakeAkamai):
        def get(self, path, params=None, headers=None):
            if path == "/papi/v1/properties":
                raise AkamaiHttpError(429, path)
            return super().get(path, params, headers)

    s = akamai_scan(env, Broken())
    assert s.status == "PARTIAL"
    assert store.db.akamai_raw.count_documents({"resource_type": "property_version", "deleted_at": {"$ne": None}}) == 0
    row = store.db.collection_status.find_one({"scan_id": s.scan_id, "api": "papi_properties"})
    assert row["status"] == "THROTTLED_GIVEUP"


def test_missing_credentials_is_one_error_row_not_a_crash(env, monkeypatch):
    settings, spec, store = env
    settings.akamai = [AkamaiAccountSettings(name="envacct", env_prefix="AKAMAI_TEST")]
    for n in ("HOST", "CLIENT_TOKEN", "CLIENT_SECRET", "ACCESS_TOKEN"):
        monkeypatch.delenv(f"AKAMAI_TEST_{n}", raising=False)
    s = run_scan(settings, spec, store, flt=ScanFilter(services={"akamai"}))
    assert s.status == "FAILED"
    row = store.db.collection_status.find_one({"scan_id": s.scan_id, "service": "akamai"})
    assert row["status"] == "ERROR" and "AKAMAI_TEST_HOST" in row["error"]


def test_filters_decide_whether_akamai_runs():
    acct = cfg()
    assert ScanFilter().wants_akamai(acct) and ScanFilter(services={"akamai"}).wants_akamai(acct)
    assert not ScanFilter(services={"s3"}).wants_akamai(acct)
    assert not ScanFilter(tier=2).wants_akamai(acct) and ScanFilter(tier=1).wants_akamai(acct)
    assert not ScanFilter(accounts={"123456789012"}).wants_akamai(acct) and ScanFilter(accounts={"main"}).wants_akamai(acct)


def test_akamai_only_run_does_not_open_aws_accounts():
    from cspm_collector.core.config import AccountSettings

    opened = []

    def no_aws(acct):
        opened.append(acct.account_id)
        raise AssertionError("an Akamai-only run must not touch AWS")

    settings = Settings(accounts=[AccountSettings(account_id="111111111111", name="a")], akamai=[cfg()])
    store = Store(mongomock.MongoClient()["cspm"], MongoSettings())
    s = run_scan(settings, CollectSpec(spec_version="t", services=[]), store, flt=ScanFilter(services={"akamai"}),
                 session_factory=no_aws, akamai_client_factory=lambda acct: FakeAkamai())
    assert opened == [] and s.status == "COMPLETED"
    assert store.db.scans.find_one({"scan_id": s.scan_id})["accounts"] == ["akamai:main"]


# --------------------------------------------------------------------------- network list usage of the AppSec policies
def test_appsec_collects_ip_geo_firewall_bypass_lists_and_custom_rules_with_the_policy_meta():
    res = AkamaiCollector(FakeAkamai(), cfg(properties=False, network_lists=False)).collect()
    fw = {r.resource_id: r for r in docs(res, "appsec_ip_geo_firewall")}
    assert set(fw) == {"111|pol1", "222|pol1"}  # 222 has no production / staging version: its latest one is used
    one = fw["111|pol1"]
    assert one.config["ipControls"]["blockedIPNetworkLists"]["networkList"] == ["1_BLOCK"]  # the API answer, untouched
    assert one.extra["config_id"] == 111 and one.extra["policy_id"] == "pol1" and one.extra["version"] == 5
    assert one.extra["version_source"] == "production" and one.extra["config_name"] == "WAF"

    bypass = {r.resource_id: r for r in docs(res, "appsec_bypass_network_lists")}
    assert "111" in bypass and bypass["111"].config["networkLists"][0]["id"] == "2_BYPASS"
    assert bypass["111"].extra["version"] == 5

    rules = {r.resource_id: r for r in docs(res, "appsec_custom_rule")}
    assert set(rules) == {"111|70001", "222|70001"}  # the deleted rule 70002 is not collected
    rule = rules["111|70001"]
    assert rule.extra["rule_id"] == 70001 and rule.extra["rule_version"] == 3 and rule.extra["config_id"] == 111
    assert rule.config["conditions"][0]["value"] == ["1_BLOCK"]  # the detail answer, with the conditions


def test_appsec_network_list_usage_status_rows_count_the_documents():
    res = AkamaiCollector(FakeAkamai(), cfg(properties=False, network_lists=False)).collect()
    rows = {r.api: r for r in res.statuses}
    assert rows["appsec_ip_geo_firewall"].resource_count == len(docs(res, "appsec_ip_geo_firewall"))
    assert rows["appsec_ip_geo_firewall"].resource_type == "appsec_ip_geo_firewall" and rows["appsec_ip_geo_firewall"].affects_sweep
    assert rows["appsec_bypass_network_lists"].resource_count == len(docs(res, "appsec_bypass_network_lists"))
    assert rows["appsec_custom_rules"].resource_count == len(docs(res, "appsec_custom_rule"))


def test_a_failed_ip_geo_call_is_recorded_and_blocks_only_that_types_sweep():
    res = AkamaiCollector(FakeAkamai(fail={"/ip-geo-firewall"}), cfg(properties=False, network_lists=False)).collect()
    assert docs(res, "appsec_ip_geo_firewall") == [] and docs(res, "appsec_policy")  # the rest still arrives
    row = next(r for r in res.statuses if r.api == "appsec_ip_geo_firewall")
    assert row.status is not Status.SUCCESS and row.affects_sweep


def test_feature_not_available_in_the_product_is_not_a_failure():
    res = AkamaiCollector(FakeAkamai(no_bypass=True), cfg(properties=False, network_lists=False)).collect()
    row = next(r for r in res.statuses if r.api == "appsec_bypass_network_lists")
    assert row.status is Status.NOT_SUPPORTED and docs(res, "appsec_bypass_network_lists") == []
    assert docs(res, "appsec_ip_geo_firewall") and docs(res, "appsec_custom_rule")  # everything else still arrives
    from cspm_collector.storage.sweep import derive_scan_status
    assert derive_scan_status(res.statuses) == "COMPLETED"  # NOT_SUPPORTED is a valid outcome, the scan is not PARTIAL


def test_policy_custom_rules_are_stored_per_policy_with_their_actions():
    res = AkamaiCollector(FakeAkamai(), cfg(properties=False, network_lists=False)).collect()
    docs_ = {r.resource_id: r for r in docs(res, "appsec_policy_custom_rules")}
    assert set(docs_) == {"111|pol1", "222|pol1"}
    one = docs_["111|pol1"]
    assert one.config == {"customRules": [{"ruleId": 70001, "name": "deny-ip", "action": "deny", "isDeleted": False}]}
    assert one.extra["policy_id"] == "pol1" and one.extra["config_id"] == 111 and one.extra["version"] == 5


class Renamed(FakeAkamai):
    """Akamai changed a field name: the answer is a non-empty object without the field we read."""

    def get(self, path, params=None, headers=None):
        data = super().get(path, params, headers)
        if path == "/network-list/v2/network-lists":
            return {"lists": data["networkLists"], "links": {}}
        if path == "/appsec/v1/configs":
            return {}  # an empty object is "nothing there", not a format change
        return data


def test_a_changed_response_format_is_an_error_not_an_empty_result():
    res = AkamaiCollector(Renamed(), cfg(properties=False)).collect()
    row = next(r for r in res.statuses if r.api == "network_lists")
    assert row.status is Status.ERROR and row.error_code == "UNEXPECTED_RESPONSE" and row.affects_sweep
    assert "lists" in row.error and docs(res, "network_list") == []
    configs = [r for r in res.statuses if r.api == "appsec_configs"]
    assert configs and configs[0].status is Status.SUCCESS  # {} is an empty answer


def test_scan_writes_the_akamai_edges_and_the_sweep_removes_those_of_a_property_that_is_gone(env):
    store = env[2]
    akamai_scan(env, FakeAkamai())
    origin = list(store.db.edges.find({"rel": "origin", "dst_id": "alb-1.elb.amazonaws.com", "deleted_at": None}))
    assert {e["src_id"] for e in origin} == {"prp_1|PRODUCTION", "prp_1|STAGING", "prp_3|PRODUCTION", "prp_3|STAGING"}
    assert {e["dst_id"] for e in store.db.edges.find({"rel": "uses_policy"})} == {"111|pol1", "222|pol1"}  # a match target per configuration
    assert store.db.edges.count_documents({"rel": "blocks_list", "dst_id": "1_BLOCK"}) >= 2  # the policies' firewall lists
    gone = FakeAkamai(properties=[p for p in FakeAkamai().properties if p["propertyId"] != "prp_3"])
    akamai_scan(env, gone)
    assert {e["src_id"] for e in store.db.edges.find({"rel": "origin", "deleted_at": None})} == {"prp_1|PRODUCTION", "prp_1|STAGING"}
