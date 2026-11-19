"""Flow-chart services (Route 53, CloudFront, ELBv2/ELB, WAF, ACM, Auto Scaling) on moto: one shared world."""
import json
import os

import boto3
import pytest
from moto import mock_aws

from cspm_collector.core.config import AccountSettings  # noqa: F401
from cspm_collector.spec.loader import load_spec

from flow_helpers import FLOW, R, SPEC, build_world, make_env, one, row, scan

@pytest.fixture(scope="module")
def world():
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_DEFAULT_REGION": R}.items():
        os.environ.setdefault(k, v)
    with mock_aws():
        ids = build_world()
        env = make_env()
        summary = scan(env)
        yield {"store": env[2], "summary": summary, "ids": ids, "sid": summary.scan_id}


def test_flow_services_are_enabled_tier1():
    spec = {s.service: s for s in load_spec(SPEC).services}
    for name in FLOW:
        assert spec[name].enabled and spec[name].tier == 1, name
    assert spec["wafv2_cloudfront"].scope == "global" and spec["wafv2"].scope == "regional"


def test_route53_records_are_documents_with_all_policy_fields(world):
    s, ids = world["store"], world["ids"]
    zone = one(s, "route53", "hosted_zone")
    assert zone["resource_id"] == ids["zone"] and zone["arn"] == f"arn:aws:route53:::hostedzone/{ids['zone']}"
    assert zone["tags"] == [{"key": "env", "value": "prod"}] and "get_hosted_zone" in zone["config"]["_details"]

    recs = {r["resource_id"]: r for r in s.db.resources.find({"service": "route53", "resource_type": "record_set"})}
    a = recs[f"{ids['zone']}|www.example.com.|A|a"]  # SetIdentifier is part of the identity: weighted pair stays 2 docs
    assert a["config"]["Weight"] == 10 and a["config"]["SetIdentifier"] == "a" and a["config"]["TTL"] == 60
    assert recs[f"{ids['zone']}|www.example.com.|A|b"]["config"]["Weight"] == 90
    assert a["hosted_zone_name"] == "example.com." and a["parent"] == {"resource_type": "hosted_zone", "resource_id": ids["zone"]}
    assert len(recs) == 5  # NS + SOA + three created


def test_route53_health_check_and_status_rows(world):
    s, sid = world["store"], world["sid"]
    assert one(s, "route53", "health_check")["arn"].startswith("arn:aws:route53:::healthcheck/")
    assert row(s, sid, "route53", "list_resource_record_sets")["resource_count"] == 5
    skipped = row(s, sid, "route53", "get_health_check_status")
    assert skipped["status"] == "SKIPPED" and "--collect-health-check-status" in skipped["error"]


def test_elbv2_hierarchy_listener_rule_target_group(world):
    s, ids = world["store"], world["ids"]
    lb = one(s, "elbv2", "load_balancer")
    assert lb["resource_id"] == ids["lb"] and lb["config"]["DNSName"]
    assert lb["tags"] == [{"key": "app", "value": "web"}]
    assert "describe_load_balancer_attributes" in lb["config"]["_details"]
    assert "describe_rules" not in one(s, "elbv2", "listener")["config"].get("_details", {})  # rules are documents

    lis = one(s, "elbv2", "listener")
    assert lis["resource_id"] == ids["listener"] and lis["load_balancer_arn"] == ids["lb"]
    assert lis["parent"] == {"resource_type": "load_balancer", "resource_id": ids["lb"]}
    assert row(s, world["sid"], "elbv2", "describe_listener_certificates")["status"] == "SUCCESS"
    assert row(s, world["sid"], "elbv2", "describe_rules")["resource_count"] == 2

    rules = list(s.db.resources.find({"service": "elbv2", "resource_type": "listener_rule"}))
    assert len(rules) == 2 and all(r["listener_arn"] == ids["listener"] and r["load_balancer_arn"] == ids["lb"] for r in rules)
    custom = next(r for r in rules if r["config"]["Priority"] == "10")
    assert custom["config"]["Conditions"][0]["Values"] == ["a.example.com"]
    assert custom["config"]["Actions"][0]["ForwardConfig"]["TargetGroups"][0]["Weight"] == 5  # weight kept raw

    tg = one(s, "elbv2", "target_group")
    assert tg["resource_id"] == ids["tg"] and {"describe_target_group_attributes", "describe_target_health"} <= set(tg["config"]["_details"])
    assert one(s, "elbv2", "ssl_policy")


def test_classic_elb_wafv2_acm_cloudfront(world):
    s = world["store"]
    elb = one(s, "elb", "load_balancer", resource_id="classic1")
    assert elb["config"]["DNSName"] and "describe_load_balancer_attributes" in elb["config"]["_details"]

    acl = one(s, "wafv2", "web_acl")
    assert acl["arn"] == world["ids"]["acl"] and "get_web_acl" in acl["config"]["_details"]
    assert row(s, world["sid"], "wafv2", "get_logging_configuration")["status"] == "SUCCESS"  # none configured = no error
    cf_acl = one(s, "wafv2_cloudfront", "web_acl")
    assert cf_acl["region"] == "global" and cf_acl["config"]["Name"] == "cfacl"

    # IP sets with their addresses (the content an ACL search needs, not only the ARN a rule refers to)
    ipset = one(s, "wafv2", "ip_set")
    assert ipset["arn"] == world["ids"]["ipset"] and ipset["resource_id"] == world["ids"]["ipset"]
    assert sorted(ipset["config"]["_details"]["get_ip_set"]["IPSet"]["Addresses"]) == ["10.0.0.0/8", "203.0.113.5/32"]
    assert row(s, world["sid"], "wafv2", "get_ip_set")["status"] == "SUCCESS"
    cf_ipset = one(s, "wafv2_cloudfront", "ip_set")
    assert cf_ipset["region"] == "global" and cf_ipset["config"]["_details"]["get_ip_set"]["IPSet"]["Addresses"] == ["198.51.100.0/24"]

    # the relationships written down while collecting: the web ACL rule -> the IP set (a negated Block rule), joined by _id
    ref = s.coll("edges").find_one({"rel": "references_ip_set"})
    assert ref["dst_id"] == world["ids"]["ipset"] and ref["src_key"] == acl["_id"] and ref["dst_key"] == ipset["_id"]
    assert ref["attrs"] == {"rule": "block-ips", "priority": 1, "action": "Block", "negated": True}
    assert s.coll("edges").find_one({"rel": "belongs_to", "dst_type": "load_balancer"}) is not None  # listener -> its load balancer
    assert s.coll("edges").find_one({"rel": "has_hostname", "service": "elb"}) is not None  # the classic ELB's DNS name

    cert = one(s, "acm", "certificate")
    assert cert["config"]["_details"]["describe_certificate"]["Certificate"]["DomainName"] == "example.com"
    assert row(s, world["sid"], "acm", "list_certificates")["status"] == "SUCCESS"  # explicit keyTypes accepted

    dist = one(s, "cloudfront", "distribution")
    assert dist["region"] == "global" and dist["arn"].startswith("arn:aws:cloudfront::")
    assert dist["config"]["Aliases"]["Items"] == ["cdn.example.com"]
    assert "ETag" in dist["config"]["_details"]["get_distribution_config"]


def test_autoscaling_userdata_masked_and_not_stored(world):
    s = world["store"]
    lc = one(s, "autoscaling", "launch_configuration", resource_id="lc1")
    assert lc["config"]["UserData"] == "***MASKED***"
    assert one(s, "autoscaling", "auto_scaling_group", resource_id="asg1")["config"]["MinSize"] == 0
    assert "hunter2" not in json.dumps([d for c in s.db.list_collection_names() for d in s.db[c].find({})], default=str)
