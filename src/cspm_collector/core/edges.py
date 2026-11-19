"""Relationships between the collected resources, extracted while they are collected.

A stored resource is one document; "which security groups does this instance use", "which web ACL protects this load
balancer", "which Akamai property serves this hostname and where is its origin" are facts spread over several of them.
They are written down here as *edges* (one document each, collection ``edges``) so that a reader can follow a chain with
indexed lookups instead of parsing every configuration again.

An edge is ``source --rel--> destination``:

* the source is always a stored resource (its key is ``src_key``, so ``resources._id == src_key``);
* the destination is another resource when the extractor knows its identity (then ``dst_key`` is its ``_id`` too), or a
  *pseudo node* that is only a name: ``hostname`` (lower case, no trailing dot) and ``ip``. Pseudo nodes are what joins
  systems: a CloudFront origin, an ALB's ``DNSName``, a Route 53 record and an Akamai origin all point at the same
  ``hostname`` node.

Every edge carries the account / region / service / resource type of its SOURCE, so the sweep that soft-deletes what a
complete scan no longer saw works on edges exactly as it does on resources. Extractors are plain functions over the
raw ``ResourceRecord`` (before storage escapes keys or chunks large configurations) and never raise: a configuration of
an unexpected shape yields no edges.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from cspm_collector.storage.records import ResourceRecord, resource_key


@dataclass(frozen=True)
class Ref:
    """A destination: another resource (``service`` is set) or a pseudo node (``hostname``, ``ip``)."""

    type: str
    id: str
    service: str | None = None
    region: str | None = None
    account_id: str | None = None  # None: the source's account


@dataclass
class Edge:
    rel: str
    dst: Ref
    attrs: dict = field(default_factory=dict)


def hostname(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    host = value.strip().lower().rstrip(".")
    return host or None


def _list(x: Any) -> list:
    return x if isinstance(x, list) else []


def _d(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def host_ref(value: Any) -> Ref | None:
    h = hostname(value)
    return Ref("hostname", h) if h else None


def ip_ref(value: Any) -> Ref | None:
    return Ref("ip", value) if isinstance(value, str) and value else None


def ref_from_arn(arn: Any, account_id: str | None = None) -> Ref | None:
    """The resource an ARN names, for the kinds this module knows (the resource id of those is the ARN itself, except
    CloudFront distributions)."""
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return None
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return None
    _, _, service, region, account, resource = parts
    account = account or account_id
    if service == "elasticloadbalancing":
        if resource.startswith("loadbalancer/"):
            return Ref("load_balancer", arn, "elbv2", region, account)
        if resource.startswith("targetgroup/"):
            return Ref("target_group", arn, "elbv2", region, account)
    if service == "wafv2":
        scope, _, rest = resource.partition("/")
        kind = rest.split("/", 1)[0]
        svc, reg = ("wafv2_cloudfront", "global") if scope == "global" else ("wafv2", region)
        kinds = {"webacl": "web_acl", "ipset": "ip_set", "rulegroup": "rule_group"}
        if kind in kinds:
            return Ref(kinds[kind], arn, svc, reg, account)
    if service == "cloudfront" and resource.startswith("distribution/"):
        return Ref("distribution", resource.split("/", 1)[1], "cloudfront", "global", account)
    return None


def _same_region(rec: ResourceRecord, type_: str, id_: Any, service: str) -> Ref | None:
    return Ref(type_, id_, service, rec.region) if isinstance(id_, str) and id_ else None


def _edges(*pairs: tuple[str, Ref | None, dict | None]) -> list[Edge]:
    return [Edge(rel, ref, attrs or {}) for rel, ref, attrs in pairs if ref is not None]


# ------------------------------------------------------------------------------------------------ AWS: networking
def ec2_instance(rec: ResourceRecord) -> list[Edge]:
    c = _d(rec.config)
    out = [("uses_security_group", _same_region(rec, "security_group", g.get("GroupId"), "ec2"), None) for g in _list(c.get("SecurityGroups")) if isinstance(g, dict)]
    out.append(("in_subnet", _same_region(rec, "subnet", c.get("SubnetId"), "vpc"), None))
    out += [("has_network_interface", _same_region(rec, "network_interface", n.get("NetworkInterfaceId"), "ec2"), None)
            for n in _list(c.get("NetworkInterfaces")) if isinstance(n, dict)]
    out.append(("has_public_ip", ip_ref(c.get("PublicIpAddress")), None))
    return _edges(*out)


def ec2_network_interface(rec: ResourceRecord) -> list[Edge]:
    c = _d(rec.config)
    out = [("uses_security_group", _same_region(rec, "security_group", g.get("GroupId"), "ec2"), None) for g in _list(c.get("Groups")) if isinstance(g, dict)]
    out.append(("attached_to", _same_region(rec, "instance", _d(c.get("Attachment")).get("InstanceId"), "ec2"), None))
    out.append(("in_subnet", _same_region(rec, "subnet", c.get("SubnetId"), "vpc"), None))
    out.append(("has_public_ip", ip_ref(_d(c.get("Association")).get("PublicIp")), None))
    return _edges(*out)


def ec2_security_group(rec: ResourceRecord) -> list[Edge]:
    c, out = _d(rec.config), []
    for direction, key in (("ingress", "IpPermissions"), ("egress", "IpPermissionsEgress")):
        for perm in _list(c.get(key)):
            for pair in _list(_d(perm).get("UserIdGroupPairs")):
                out.append(("allows_from_security_group" if direction == "ingress" else "allows_to_security_group",
                            _same_region(rec, "security_group", _d(pair).get("GroupId"), "ec2"),
                            {"protocol": _d(perm).get("IpProtocol"), "from": _d(perm).get("FromPort"), "to": _d(perm).get("ToPort")}))
    return _edges(*out)


def ec2_elastic_ip(rec: ResourceRecord) -> list[Edge]:
    c = _d(rec.config)
    return _edges(("has_public_ip", ip_ref(c.get("PublicIp")), None),
                  ("associated_with", _same_region(rec, "instance", c.get("InstanceId"), "ec2"), None),
                  ("associated_with", _same_region(rec, "network_interface", c.get("NetworkInterfaceId"), "ec2"), None))


# ------------------------------------------------------------------------------------------------ AWS: load balancers
def _forward_targets(actions: Any) -> list[str]:
    arns: list[str] = []
    for a in _list(actions):
        a = _d(a)
        if a.get("TargetGroupArn"):
            arns.append(a["TargetGroupArn"])
        arns += [t.get("TargetGroupArn") for t in _list(_d(a.get("ForwardConfig")).get("TargetGroups")) if _d(t).get("TargetGroupArn")]
    return list(dict.fromkeys(arns))


def elbv2_load_balancer(rec: ResourceRecord) -> list[Edge]:
    c = _d(rec.config)
    out = [("uses_security_group", _same_region(rec, "security_group", g, "ec2"), None) for g in _list(c.get("SecurityGroups"))]
    out += [("in_subnet", _same_region(rec, "subnet", _d(az).get("SubnetId"), "vpc"), None) for az in _list(c.get("AvailabilityZones"))]
    out.append(("has_hostname", host_ref(c.get("DNSName")), None))
    return _edges(*out)


def elbv2_listener(rec: ResourceRecord) -> list[Edge]:
    lb = ref_from_arn(rec.extra.get("load_balancer_arn") or _d(rec.config).get("LoadBalancerArn"), rec.account_id)
    out = [("belongs_to", lb, None)]
    out += [("forwards_to", ref_from_arn(a, rec.account_id), None) for a in _forward_targets(_d(rec.config).get("DefaultActions"))]
    return _edges(*out)


def elbv2_listener_rule(rec: ResourceRecord) -> list[Edge]:
    out = [("belongs_to", Ref("listener", rec.extra["listener_arn"], "elbv2", rec.region) if rec.extra.get("listener_arn") else None, None)]
    out += [("forwards_to", ref_from_arn(a, rec.account_id), None) for a in _forward_targets(_d(rec.config).get("Actions"))]
    return _edges(*out)


def elbv2_target_group(rec: ResourceRecord) -> list[Edge]:
    c = _d(rec.config)
    out = [("attached_to", ref_from_arn(a, rec.account_id), None) for a in _list(c.get("LoadBalancerArns"))]
    health = _d(_d(c.get("_details")).get("describe_target_health"))
    for t in _list(health.get("TargetHealthDescriptions")):
        tid = _d(_d(t).get("Target")).get("Id")
        if isinstance(tid, str) and tid.startswith("i-"):
            out.append(("targets", _same_region(rec, "instance", tid, "ec2"), None))
        elif isinstance(tid, str) and tid:
            out.append(("targets", ip_ref(tid), None))
    return _edges(*out)


def elb_load_balancer(rec: ResourceRecord) -> list[Edge]:
    c = _d(rec.config)
    out = [("uses_security_group", _same_region(rec, "security_group", g, "ec2"), None) for g in _list(c.get("SecurityGroups"))]
    out += [("targets", _same_region(rec, "instance", _d(i).get("InstanceId"), "ec2"), None) for i in _list(c.get("Instances"))]
    out.append(("has_hostname", host_ref(c.get("DNSName")), None))
    return _edges(*out)


# ------------------------------------------------------------------------------------------------ AWS: WAF, CloudFront, DNS
_ACTIONS = ("Allow", "Block", "Count", "Captcha", "Challenge")


def _statement_refs(stmt: Any, negated: bool = False) -> Iterable[tuple[str, str, bool]]:
    """``(kind, arn, negated)`` of every IP set / rule group a (nested) WAF statement refers to."""
    if isinstance(stmt, list):
        for s in stmt:
            yield from _statement_refs(s, negated)
    elif isinstance(stmt, dict):
        for key, value in stmt.items():
            if key == "IPSetReferenceStatement" and _d(value).get("ARN"):
                yield "ip_set", value["ARN"], negated
            elif key == "RuleGroupReferenceStatement" and _d(value).get("ARN"):
                yield "rule_group", value["ARN"], negated
            elif key == "NotStatement":
                yield from _statement_refs(value, not negated)
            elif isinstance(value, (dict, list)):
                yield from _statement_refs(value, negated)


def wafv2_web_acl(rec: ResourceRecord) -> list[Edge]:
    details, out = _d(_d(rec.config).get("_details")), []
    for name, value in details.items():
        if name.startswith("acl_resources_"):
            out += [("protects", ref_from_arn(a, rec.account_id), None) for a in _list(_d(value).get("ResourceArns"))]
    for item in _list(_d(_d(details.get("list_distributions_by_web_acl_id")).get("DistributionList")).get("Items")):
        out.append(("protects", Ref("distribution", _d(item).get("Id"), "cloudfront", "global") if _d(item).get("Id") else None, None))
    for rule in _list(_d(_d(details.get("get_web_acl")).get("WebACL")).get("Rules")):
        rule = _d(rule)
        action = next((a for a in _ACTIONS if a in _d(rule.get("Action"))), None) or ("override:" + next(iter(_d(rule.get("OverrideAction"))), "") if rule.get("OverrideAction") else None)
        for kind, arn, negated in _statement_refs(rule.get("Statement")):
            out.append(("references_ip_set" if kind == "ip_set" else "references_rule_group", ref_from_arn(arn, rec.account_id),
                        {"rule": rule.get("Name"), "priority": rule.get("Priority"), "action": action, "negated": negated}))
    return _edges(*out)


def cloudfront_distribution(rec: ResourceRecord) -> list[Edge]:
    c = _d(rec.config)
    cfg = _d(_d(_d(c.get("_details")).get("get_distribution_config")).get("DistributionConfig"))
    acl = c.get("WebACLId") or cfg.get("WebACLId")
    out = [("protected_by", ref_from_arn(acl, rec.account_id) if acl else None, None), ("has_hostname", host_ref(c.get("DomainName")), None)]
    aliases = _d(c.get("Aliases") or cfg.get("Aliases")).get("Items")
    out += [("serves_hostname", host_ref(a), None) for a in _list(aliases)]
    origins = _d(cfg.get("Origins") or c.get("Origins")).get("Items")  # the full config first: it is what the routing is read from
    routing = _cloudfront_routing(cfg, c)
    out += [("origin", host_ref(_d(o).get("DomainName")), routing.get(_d(o).get("Id"), {"origin_id": _d(o).get("Id")}))
            for o in _list(origins)]
    return _edges(*out)


def _cloudfront_routing(cfg: dict, listed: dict) -> dict[str, dict]:
    """Per origin id: which path patterns reach it (directly or as a member of an origin group), and how those behaviors
    treat the viewer. The full distribution config is preferred; the list item has the same sections as a fallback."""
    def part(key: str) -> Any:
        return cfg.get(key) if cfg.get(key) else listed.get(key)

    groups = {_d(g).get("Id"): _d(g) for g in _list(_d(part("OriginGroups")).get("Items"))}
    behaviors = [("*", True, _d(part("DefaultCacheBehavior")))] + [
        (_d(b).get("PathPattern") or "?", False, _d(b)) for b in _list(_d(part("CacheBehaviors")).get("Items"))]
    routing: dict[str, dict] = {}
    for o in _list(_d(part("Origins")).get("Items")):
        if _d(o).get("Id") is not None:
            routing[o["Id"]] = {"origin_id": o["Id"], "default": False, "paths": [], "behaviors": [],
                                "origin_group": None, "failover_role": None}
    for path, is_default, b in behaviors:
        target = b.get("TargetOriginId")
        group = groups.get(target)
        members = [_d(m).get("OriginId") for m in _list(_d(_d(group).get("Members")).get("Items"))] if group else [target]
        for i, origin_id in enumerate(members):
            r = routing.get(origin_id)
            if r is None:
                continue
            r["default"] = r["default"] or is_default
            if path not in r["paths"]:
                r["paths"].append(path)
            r["behaviors"].append({"path": path, "default": is_default, "viewer_protocol": b.get("ViewerProtocolPolicy"),
                                   "methods": _d(b.get("AllowedMethods")).get("Items"), "cache_policy_id": b.get("CachePolicyId"),
                                   "target": target})
            if group:
                r["origin_group"] = target
                r["failover_role"] = "primary" if i == 0 else "secondary"
    return routing


def route53_record_set(rec: ResourceRecord) -> list[Edge]:
    c = _d(rec.config)
    out = [("has_hostname", host_ref(c.get("Name")), {"type": c.get("Type")}),
           ("points_to", host_ref(_d(c.get("AliasTarget")).get("DNSName")), {"type": c.get("Type"), "alias": True})]
    for r in _list(c.get("ResourceRecords")):
        value = _d(r).get("Value")
        ref = ip_ref(value) if c.get("Type") in ("A", "AAAA") else host_ref(value) if c.get("Type") == "CNAME" else None
        out.append(("points_to", ref, {"type": c.get("Type")}))
    return _edges(*out)


# ------------------------------------------------------------------------------------------------ AWS: ECS
def ecs_task(rec: ResourceRecord) -> list[Edge]:
    """task -> its service, the EC2 server it runs on (EC2 launch type), its private IPs (awsvpc/Fargate), its cluster."""
    x, c = rec.extra, _d(rec.config)
    cluster_arn = x.get("cluster_arn") or c.get("clusterArn")
    name = x.get("service_name")
    service = None
    if name and isinstance(cluster_arn, str) and ":cluster/" in cluster_arn:
        head, _, cluster_name = cluster_arn.partition(":cluster/")
        service = Ref("service", f"{head}:service/{cluster_name}/{name}", "ecs", rec.region)
    out = [("in_cluster", Ref("cluster", cluster_arn, "ecs", rec.region) if isinstance(cluster_arn, str) else None, None),
           ("belongs_to_service", service, None),
           ("runs_on_instance", _same_region(rec, "instance", x.get("ec2_instance_id"), "ec2"), None),
           ("runs_on_container_instance", Ref("container_instance", x["container_instance_arn"], "ecs", rec.region)
            if x.get("container_instance_arn") else None, None)]
    out += [("has_private_ip", ip_ref(ip), None) for ip in _list(x.get("private_ips"))]
    return _edges(*out)


def ecs_container_instance(rec: ResourceRecord) -> list[Edge]:
    x = rec.extra
    cluster_arn = x.get("cluster_arn")
    return _edges(("runs_on_instance", _same_region(rec, "instance", x.get("ec2_instance_id"), "ec2"), None),
                  ("in_cluster", Ref("cluster", cluster_arn, "ecs", rec.region) if isinstance(cluster_arn, str) else None, None))


# ------------------------------------------------------------------------------------------------ Akamai
def _akamai(rec: ResourceRecord, type_: str, id_: Any) -> Ref | None:
    return Ref(type_, str(id_), "akamai", "global", rec.account_id) if id_ not in (None, "") else None


def akamai_property_version(rec: ResourceRecord) -> list[Edge]:
    x = rec.extra
    return _edges(*[("serves_hostname", host_ref(h), {"network": x.get("network")}) for h in _list(x.get("hostnames"))],
                  *[("uses_edge_hostname", host_ref(h), None) for h in _list(x.get("edge_hostnames"))],
                  *[("origin", host_ref(h), {"network": x.get("network")}) for h in _list(x.get("origin_hostnames"))])


def akamai_appsec_config(rec: ResourceRecord) -> list[Edge]:
    return _edges(*[("selected_hostname", host_ref(h), None) for h in _list(rec.extra.get("hostnames"))])


def akamai_match_target(rec: ResourceRecord) -> list[Edge]:
    x = rec.extra
    pol = _akamai(rec, "appsec_policy", f"{x['config_id']}|{x['policy_id']}") if x.get("config_id") and x.get("policy_id") else None
    return _edges(("uses_policy", pol, None), *[("applies_to_hostname", host_ref(h), None) for h in _list(x.get("hostnames"))])


def akamai_ip_geo_firewall(rec: ResourceRecord) -> list[Edge]:
    c, mode, out = _d(rec.config), _d(rec.config).get("block"), []
    for section, kind in (("ipControls", "ip"), ("geoControls", "geo"), ("asnControls", "asn")):
        for key, rel in (("blockedIPNetworkLists", "blocks_list"), ("allowedIPNetworkLists", "allows_list")):
            for nl in _list(_d(_d(c.get(section)).get(key)).get("networkList")):
                out.append((rel, _akamai(rec, "network_list", nl), {"kind": kind, "mode": mode}))
    return _edges(*out)


def akamai_policy_custom_rules(rec: ResourceRecord) -> list[Edge]:
    cid = rec.extra.get("config_id")
    return _edges(*[("uses_custom_rule", _akamai(rec, "appsec_custom_rule", f"{cid}|{r['ruleId']}"), {"action": r.get("action"), "name": r.get("name")})
                    for r in _list(_d(rec.config).get("customRules")) if isinstance(r, dict) and r.get("ruleId") is not None and not r.get("isDeleted")])


def akamai_custom_rule(rec: ResourceRecord) -> list[Edge]:
    out = []
    for cond in _list(_d(rec.config).get("conditions")):
        if _d(cond).get("type") == "networkListMatch":
            for nl in _list(_d(cond).get("value")):
                out.append(("matches_list", _akamai(rec, "network_list", nl), {"positive": _d(cond).get("positiveMatch", True)}))
    return _edges(*out)


EXTRACTORS: dict[tuple[str, str], Callable[[ResourceRecord], list[Edge]]] = {
    ("ec2", "instance"): ec2_instance, ("ec2", "network_interface"): ec2_network_interface,
    ("ec2", "security_group"): ec2_security_group, ("ec2", "elastic_ip"): ec2_elastic_ip,
    ("elbv2", "load_balancer"): elbv2_load_balancer, ("elbv2", "listener"): elbv2_listener,
    ("elbv2", "listener_rule"): elbv2_listener_rule, ("elbv2", "target_group"): elbv2_target_group,
    ("elb", "load_balancer"): elb_load_balancer,
    ("ecs", "task"): ecs_task, ("ecs", "container_instance"): ecs_container_instance,
    ("wafv2", "web_acl"): wafv2_web_acl, ("wafv2_cloudfront", "web_acl"): wafv2_web_acl,
    ("cloudfront", "distribution"): cloudfront_distribution, ("route53", "record_set"): route53_record_set,
    ("akamai", "property_version"): akamai_property_version, ("akamai", "appsec_config"): akamai_appsec_config,
    ("akamai", "appsec_match_target"): akamai_match_target, ("akamai", "appsec_ip_geo_firewall"): akamai_ip_geo_firewall,
    ("akamai", "appsec_policy_custom_rules"): akamai_policy_custom_rules, ("akamai", "appsec_custom_rule"): akamai_custom_rule,
}


def edge_id(src_key: str, edge: Edge) -> str:
    raw = "|".join((src_key, edge.rel, edge.dst.type, edge.dst.id, json.dumps(edge.attrs, sort_keys=True, default=str)))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def extract_edges(records: Iterable[ResourceRecord]) -> list[dict]:
    """Edge documents of the given resources (``_id`` is stable: the same fact is the same document in every scan)."""
    docs: dict[str, dict] = {}
    for rec in records:
        fn = EXTRACTORS.get((rec.service, rec.resource_type))
        if fn is None:
            continue
        try:
            found = fn(rec)
        except Exception:  # noqa: BLE001 - an odd configuration must never break a collection
            continue
        src_key = rec.key
        for e in found:
            d = e.dst
            dst_key = None
            if d.service:
                dst_key = resource_key(d.account_id or rec.account_id, d.region or rec.region, d.service, d.type, d.id)
            doc = {"_id": edge_id(src_key, e), "account_id": rec.account_id, "region": rec.region, "service": rec.service,
                   "resource_type": rec.resource_type, "src_key": src_key, "src_id": rec.resource_id, "rel": e.rel,
                   "dst_type": d.type, "dst_id": d.id, "dst_key": dst_key, "attrs": e.attrs or None}
            docs[doc["_id"]] = doc
    return list(docs.values())
