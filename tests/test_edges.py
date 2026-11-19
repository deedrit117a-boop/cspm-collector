"""Relationships (edges) between collected resources: what is extracted, how it is stored and when it goes away."""
import mongomock

from cspm_collector.core.config import MongoSettings
from cspm_collector.core.edges import extract_edges, hostname, ref_from_arn
from cspm_collector.storage.records import ResourceRecord, resource_key
from cspm_collector.storage.store import Store

ACCT, R = "123456789012", "ap-northeast-2"
ALB = f"arn:aws:elasticloadbalancing:{R}:{ACCT}:loadbalancer/app/web/50dc6c495c0c9188"
TG = f"arn:aws:elasticloadbalancing:{R}:{ACCT}:targetgroup/web/73e2d6bc24d8a067"
ACL = f"arn:aws:wafv2:{R}:{ACCT}:regional/webacl/acl1/111"
IPSET = f"arn:aws:wafv2:{R}:{ACCT}:regional/ipset/ips1/222"


def rec(service, rtype, rid, config, extra=None, region=R, account=ACCT):
    return ResourceRecord(account, region, service, rtype, rid, config, extra=extra or {})


def edges(*records):
    return extract_edges(records)


def triples(docs):
    return sorted((d["rel"], d["dst_type"], d["dst_id"]) for d in docs)


# ----------------------------------------------------------------------------- helpers
def test_hostnames_are_normalized_and_arns_resolve_to_the_resource_they_name():
    assert hostname(" WWW.Example.COM. ") == "www.example.com" and hostname("") is None and hostname(None) is None
    lb = ref_from_arn(ALB)
    assert (lb.type, lb.service, lb.region, lb.id) == ("load_balancer", "elbv2", R, ALB)
    assert ref_from_arn(TG).type == "target_group"
    waf = ref_from_arn(f"arn:aws:wafv2:us-east-1:{ACCT}:global/webacl/cf/1")
    assert (waf.service, waf.region, waf.type) == ("wafv2_cloudfront", "global", "web_acl")
    assert ref_from_arn(f"arn:aws:wafv2:{R}:{ACCT}:regional/ipset/x/1").type == "ip_set"
    cf = ref_from_arn(f"arn:aws:cloudfront::{ACCT}:distribution/E123")
    assert (cf.type, cf.id, cf.region) == ("distribution", "E123", "global")
    assert ref_from_arn("not an arn") is None and ref_from_arn("arn:aws:s3:::bucket") is None and ref_from_arn(None) is None


# ----------------------------------------------------------------------------- AWS
def test_instance_interface_and_security_group_relations_point_at_the_resources_they_name():
    inst = rec("ec2", "instance", "i-1", {"SecurityGroups": [{"GroupId": "sg-1"}], "SubnetId": "subnet-1", "PublicIpAddress": "203.0.113.9",
                                          "NetworkInterfaces": [{"NetworkInterfaceId": "eni-1"}]})
    eni = rec("ec2", "network_interface", "eni-1", {"Groups": [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}], "Attachment": {"InstanceId": "i-1"},
                                                    "SubnetId": "subnet-1", "Association": {"PublicIp": "203.0.113.9"}})
    sg = rec("ec2", "security_group", "sg-1", {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                                                                  "UserIdGroupPairs": [{"GroupId": "sg-2"}], "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                                               "IpPermissionsEgress": [{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-3"}]}]})
    d_inst, d_eni, d_sg = edges(inst), edges(eni), edges(sg)
    assert triples(d_inst) == [("has_network_interface", "network_interface", "eni-1"), ("has_public_ip", "ip", "203.0.113.9"),
                               ("in_subnet", "subnet", "subnet-1"), ("uses_security_group", "security_group", "sg-1")]
    assert triples(d_eni) == [("attached_to", "instance", "i-1"), ("has_public_ip", "ip", "203.0.113.9"), ("in_subnet", "subnet", "subnet-1"),
                              ("uses_security_group", "security_group", "sg-1"), ("uses_security_group", "security_group", "sg-2")]
    assert triples(d_sg) == [("allows_from_security_group", "security_group", "sg-2"), ("allows_to_security_group", "security_group", "sg-3")]
    to_sg = next(d for d in d_inst if d["rel"] == "uses_security_group")
    assert to_sg["src_key"] == inst.key == resource_key(ACCT, R, "ec2", "instance", "i-1")  # joins resources._id
    assert to_sg["dst_key"] == resource_key(ACCT, R, "ec2", "security_group", "sg-1")
    assert next(d for d in d_inst if d["rel"] == "has_public_ip")["dst_key"] is None  # a pseudo node has no document
    assert {d["account_id"] for d in d_inst} == {ACCT} and {d["service"] for d in d_inst} == {"ec2"}  # the source's scope


def test_load_balancer_listener_rule_and_target_group_relations():
    lb = rec("elbv2", "load_balancer", ALB, {"SecurityGroups": ["sg-1"], "DNSName": "Web-1.ap-northeast-2.elb.amazonaws.com.",
                                             "AvailabilityZones": [{"SubnetId": "subnet-a"}, {"SubnetId": "subnet-b"}]})
    lst = rec("elbv2", "listener", f"{ALB}/l1", {"DefaultActions": [{"Type": "forward", "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": TG}]}}]},
              extra={"load_balancer_arn": ALB})
    rule = rec("elbv2", "listener_rule", f"{ALB}/l1/r1", {"Actions": [{"Type": "forward", "TargetGroupArn": TG}]}, extra={"listener_arn": f"{ALB}/l1"})
    tg = rec("elbv2", "target_group", TG, {"LoadBalancerArns": [ALB], "_details": {"describe_target_health": {"TargetHealthDescriptions": [
        {"Target": {"Id": "i-9"}}, {"Target": {"Id": "10.0.1.5"}}]}}})
    assert triples(edges(lb)) == [("has_hostname", "hostname", "web-1.ap-northeast-2.elb.amazonaws.com"), ("in_subnet", "subnet", "subnet-a"),
                                  ("in_subnet", "subnet", "subnet-b"), ("uses_security_group", "security_group", "sg-1")]
    assert triples(edges(lst)) == [("belongs_to", "load_balancer", ALB), ("forwards_to", "target_group", TG)]
    assert triples(edges(rule)) == [("belongs_to", "listener", f"{ALB}/l1"), ("forwards_to", "target_group", TG)]
    assert triples(edges(tg)) == [("attached_to", "load_balancer", ALB), ("targets", "instance", "i-9"), ("targets", "ip", "10.0.1.5")]
    fwd = next(d for d in edges(lst) if d["rel"] == "forwards_to")
    assert fwd["dst_key"] == resource_key(ACCT, R, "elbv2", "target_group", TG)


def test_web_acl_protects_resources_and_references_ip_sets_with_the_rule_and_action():
    stmt = {"AndStatement": {"Statements": [{"ByteMatchStatement": {}}, {"NotStatement": {"Statement": {"IPSetReferenceStatement": {"ARN": IPSET}}}}]}}
    acl = rec("wafv2", "web_acl", ACL, {"_details": {
        "acl_resources_alb": {"ResourceArns": [ALB]}, "acl_resources_api_gateway": {"ResourceArns": []},
        "get_web_acl": {"WebACL": {"Rules": [
            {"Name": "allow-office", "Priority": 1, "Action": {"Allow": {}}, "Statement": {"IPSetReferenceStatement": {"ARN": IPSET}}},
            {"Name": "geo-and-not", "Priority": 2, "Action": {"Block": {}}, "Statement": stmt},
            {"Name": "managed", "Priority": 3, "OverrideAction": {"None": {}}, "Statement": {"RuleGroupReferenceStatement": {"ARN": f"arn:aws:wafv2:{R}:{ACCT}:regional/rulegroup/rg/3"}}}]}}}})
    d = edges(acl)
    assert triples(d) == [("protects", "load_balancer", ALB), ("references_ip_set", "ip_set", IPSET), ("references_ip_set", "ip_set", IPSET),
                          ("references_rule_group", "rule_group", f"arn:aws:wafv2:{R}:{ACCT}:regional/rulegroup/rg/3")]
    by_rule = {x["attrs"]["rule"]: x["attrs"] for x in d if x["rel"] == "references_ip_set"}
    assert by_rule["allow-office"] == {"rule": "allow-office", "priority": 1, "action": "Allow", "negated": False}
    assert by_rule["geo-and-not"]["action"] == "Block" and by_rule["geo-and-not"]["negated"] is True  # inside NotStatement
    assert next(x for x in d if x["rel"] == "references_rule_group")["attrs"]["action"] == "override:None"
    cf = rec("wafv2_cloudfront", "web_acl", f"arn:aws:wafv2:us-east-1:{ACCT}:global/webacl/cf/9", {"_details": {
        "list_distributions_by_web_acl_id": {"DistributionList": {"Items": [{"Id": "E123", "ARN": "x"}]}}}}, region="global")
    assert triples(edges(cf)) == [("protects", "distribution", "E123")]
    assert edges(cf)[0]["dst_key"] == resource_key(ACCT, "global", "cloudfront", "distribution", "E123")


def test_cloudfront_and_route53_connect_through_hostnames():
    cfd = rec("cloudfront", "distribution", "E123", {"DomainName": "d1.cloudfront.net", "WebACLId": f"arn:aws:wafv2:us-east-1:{ACCT}:global/webacl/cf/9",
                                                   "Aliases": {"Items": ["CDN.example.com"]}, "Origins": {"Items": [{"DomainName": "origin.example.com"}]}},
              region="global")
    assert triples(edges(cfd)) == [("has_hostname", "hostname", "d1.cloudfront.net"), ("origin", "hostname", "origin.example.com"),
                                   ("protected_by", "web_acl", f"arn:aws:wafv2:us-east-1:{ACCT}:global/webacl/cf/9"), ("serves_hostname", "hostname", "cdn.example.com")]
    alias = rec("route53", "record_set", "www|A", {"Name": "www.example.com.", "Type": "A", "AliasTarget": {"DNSName": "web-1.elb.amazonaws.com."}}, region="global")
    cname = rec("route53", "record_set", "api|CNAME", {"Name": "api.example.com.", "Type": "CNAME", "ResourceRecords": [{"Value": "api.example.com.edgekey.net."}]}, region="global")
    plain = rec("route53", "record_set", "ip|A", {"Name": "ip.example.com.", "Type": "A", "ResourceRecords": [{"Value": "198.51.100.7"}]}, region="global")
    assert ("points_to", "hostname", "web-1.elb.amazonaws.com") in triples(edges(alias))
    assert ("points_to", "hostname", "api.example.com.edgekey.net") in triples(edges(cname))
    assert ("points_to", "ip", "198.51.100.7") in triples(edges(plain))


# ----------------------------------------------------------------------------- Akamai
def test_akamai_documents_link_hostnames_policies_network_lists_and_custom_rules():
    a = "akamai:main"
    prop = rec("akamai", "property_version", "prp_1|PRODUCTION", {}, region="global", account=a, extra={
        "network": "PRODUCTION", "hostnames": ["www.example.com"], "edge_hostnames": ["www.example.com.edgekey.net"], "origin_hostnames": ["web-1.elb.amazonaws.com"]})
    assert triples(edges(prop)) == [("origin", "hostname", "web-1.elb.amazonaws.com"), ("serves_hostname", "hostname", "www.example.com"),
                                    ("uses_edge_hostname", "hostname", "www.example.com.edgekey.net")]
    mt = rec("akamai", "appsec_match_target", "111|1", {}, region="global", account=a, extra={"config_id": 111, "policy_id": "pol1", "hostnames": ["www.example.com"]})
    d = edges(mt)
    assert triples(d) == [("applies_to_hostname", "hostname", "www.example.com"), ("uses_policy", "appsec_policy", "111|pol1")]
    assert next(x for x in d if x["rel"] == "uses_policy")["dst_key"] == resource_key(a, "global", "akamai", "appsec_policy", "111|pol1")
    fw = rec("akamai", "appsec_ip_geo_firewall", "111|pol1", {"block": "blockSpecificIPGeo", "ipControls": {
        "blockedIPNetworkLists": {"networkList": ["1_BLOCK", "2_BLOCK"]}, "allowedIPNetworkLists": {"networkList": ["3_ALLOW"]}},
        "geoControls": {"blockedIPNetworkLists": {"networkList": ["4_GEO"]}}, "asnControls": {"blockedIPNetworkLists": {"networkList": ["5_ASN"]}}},
        region="global", account=a, extra={"config_id": 111})
    got = {(x["rel"], x["dst_id"], x["attrs"]["kind"]) for x in edges(fw)}
    assert got == {("blocks_list", "1_BLOCK", "ip"), ("blocks_list", "2_BLOCK", "ip"), ("allows_list", "3_ALLOW", "ip"),
                   ("blocks_list", "4_GEO", "geo"), ("blocks_list", "5_ASN", "asn")}
    used = rec("akamai", "appsec_policy_custom_rules", "111|pol1", {"customRules": [
        {"ruleId": 70001, "name": "deny-ip", "action": "deny"}, {"ruleId": 70002, "action": "alert", "isDeleted": True}]},
        region="global", account=a, extra={"config_id": 111})
    assert [(x["rel"], x["dst_id"], x["attrs"]["action"]) for x in edges(used)] == [("uses_custom_rule", "111|70001", "deny")]
    cr = rec("akamai", "appsec_custom_rule", "111|70001", {"conditions": [{"type": "networkListMatch", "positiveMatch": False, "value": ["1_BLOCK"]},
                                                                         {"type": "pathMatch", "value": ["/x"]}]}, region="global", account=a, extra={"config_id": 111})
    assert [(x["rel"], x["dst_id"], x["attrs"]["positive"]) for x in edges(cr)] == [("matches_list", "1_BLOCK", False)]


# ----------------------------------------------------------------------------- robustness and storage
def test_odd_configurations_and_unknown_types_yield_no_edges_and_never_raise():
    odd = [rec("ec2", "instance", "i-1", None), rec("ec2", "instance", "i-2", "text"), rec("ec2", "security_group", "sg", {"IpPermissions": "x"}),
           rec("elbv2", "listener", "l", {"DefaultActions": [None, 5]}), rec("wafv2", "web_acl", "a", {"_details": {"get_web_acl": []}}),
           rec("s3", "bucket", "b", {"Name": "b"}), rec("cloudfront", "distribution", "E1", {"Origins": {"Items": [None]}})]
    assert edges(*odd) == []


def test_the_same_fact_is_the_same_edge_in_every_scan_and_a_changed_attribute_is_a_new_one():
    inst = rec("ec2", "instance", "i-1", {"SecurityGroups": [{"GroupId": "sg-1"}]})
    assert [d["_id"] for d in edges(inst)] == [d["_id"] for d in edges(inst)]
    two = rec("wafv2", "web_acl", ACL, {"_details": {"get_web_acl": {"WebACL": {"Rules": [
        {"Name": "a", "Priority": 1, "Action": {"Allow": {}}, "Statement": {"IPSetReferenceStatement": {"ARN": IPSET}}},
        {"Name": "b", "Priority": 2, "Action": {"Block": {}}, "Statement": {"IPSetReferenceStatement": {"ARN": IPSET}}}]}}}})
    assert len(edges(two)) == 2  # two rules on the same IP set are two facts


def test_store_upserts_revives_and_the_sweep_removes_what_a_complete_scan_no_longer_saw():
    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()
    both = edges(rec("ec2", "instance", "i-1", {"SecurityGroups": [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}]}))
    assert store.save_edges("s1", both) == 2 and store.coll("edges").count_documents({}) == 2
    one = edges(rec("ec2", "instance", "i-1", {"SecurityGroups": [{"GroupId": "sg-1"}]}))
    store.save_edges("s2", one)
    from cspm_collector.storage.sweep import SweepScope
    assert store.sweep("s2", [SweepScope(ACCT, R, "ec2", None)], collection="edges") == 1  # sg-2 is no longer there
    live = {d["dst_id"] for d in store.coll("edges").find({"deleted_at": None})}
    assert live == {"sg-1"}
    store.save_edges("s3", both)  # it came back: revived, not duplicated
    assert store.coll("edges").count_documents({}) == 2 and store.coll("edges").count_documents({"deleted_at": None}) == 2
    assert store.coll("edges").find_one({"dst_id": "sg-2"})["scan_id"] == "s3"


def test_cloudfront_origin_edges_carry_the_paths_that_reach_them():
    cfg = {"DistributionConfig": {
        "Origins": {"Items": [{"Id": "lb", "DomainName": "alb.example.com"}, {"Id": "s3", "DomainName": "b.s3.amazonaws.com"},
                              {"Id": "dr", "DomainName": "dr.example.com"}, {"Id": "unused", "DomainName": "old.example.com"}]},
        "OriginGroups": {"Items": [{"Id": "grp", "Members": {"Items": [{"OriginId": "lb"}, {"OriginId": "dr"}]}}]},
        "DefaultCacheBehavior": {"TargetOriginId": "s3", "ViewerProtocolPolicy": "redirect-to-https",
                                 "AllowedMethods": {"Items": ["GET", "HEAD"]}, "CachePolicyId": "cp-1"},
        "CacheBehaviors": {"Items": [{"PathPattern": "/api/*", "TargetOriginId": "grp", "ViewerProtocolPolicy": "https-only",
                                      "AllowedMethods": {"Items": ["GET", "POST"]}}]}}}
    cfd = rec("cloudfront", "distribution", "E9", {"DomainName": "d9.cloudfront.net", "Origins": {"Items": [{"Id": "lb", "DomainName": "alb.example.com"}]},
                                                     "_details": {"get_distribution_config": cfg}})
    by_host = {e["dst_id"]: e["attrs"] for e in edges(cfd) if e["rel"] == "origin"}
    assert by_host["alb.example.com"]["paths"] == ["/api/*"] and by_host["alb.example.com"]["default"] is False
    assert by_host["alb.example.com"]["origin_group"] == "grp" and by_host["alb.example.com"]["failover_role"] == "primary"
    assert by_host["dr.example.com"]["failover_role"] == "secondary"
    assert by_host["b.s3.amazonaws.com"]["paths"] == ["*"] and by_host["b.s3.amazonaws.com"]["default"] is True
    b = by_host["b.s3.amazonaws.com"]["behaviors"][0]
    assert b["viewer_protocol"] == "redirect-to-https" and b["methods"] == ["GET", "HEAD"] and b["cache_policy_id"] == "cp-1"
    assert by_host["alb.example.com"]["behaviors"][0]["viewer_protocol"] == "https-only"
    assert by_host["old.example.com"]["paths"] == [] and by_host["old.example.com"]["origin_id"] == "unused"


def test_cloudfront_routing_falls_back_to_the_list_item_without_the_full_config():
    cfd = rec("cloudfront", "distribution", "E8", {"DomainName": "d8.cloudfront.net",
              "Origins": {"Items": [{"Id": "o1", "DomainName": "a.example.com"}]},
              "DefaultCacheBehavior": {"TargetOriginId": "o1", "ViewerProtocolPolicy": "allow-all"}})
    origin = [e for e in edges(cfd) if e["rel"] == "origin"][0]
    assert origin["attrs"]["default"] is True and origin["attrs"]["behaviors"][0]["viewer_protocol"] == "allow-all"
