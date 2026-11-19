"""Shared setup for the flow-service tests."""
import json
import os
from pathlib import Path

import boto3
import mongomock

from cspm_collector.collectors.base import CollectOptions
from cspm_collector.core.config import AccountSettings, MongoSettings, Settings
from cspm_collector.core.scan import ScanFilter, run_scan
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
R = "us-east-1"
FLOW = {"route53", "cloudfront", "elbv2", "elb", "wafv2", "wafv2_cloudfront", "waf", "waf_global", "acm", "autoscaling"}
VIS = {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "m"}


def build_world():
    c = lambda name: boto3.client(name, region_name=R)  # noqa: E731
    ids = {}
    r53 = c("route53")
    zid = r53.create_hosted_zone(Name="example.com.", CallerReference="r1")["HostedZone"]["Id"]
    ids["zone"] = zid.split("/")[-1]
    r53.change_resource_record_sets(HostedZoneId=zid, ChangeBatch={"Changes": [
        {"Action": "CREATE", "ResourceRecordSet": {"Name": "www.example.com.", "Type": "A", "SetIdentifier": "a",
                                                    "Weight": 10, "TTL": 60, "ResourceRecords": [{"Value": "1.2.3.4"}]}},
        {"Action": "CREATE", "ResourceRecordSet": {"Name": "www.example.com.", "Type": "A", "SetIdentifier": "b",
                                                    "Weight": 90, "TTL": 60, "ResourceRecords": [{"Value": "5.6.7.8"}]}},
        {"Action": "CREATE", "ResourceRecordSet": {"Name": "old.example.com.", "Type": "CNAME", "TTL": 60,
                                                    "ResourceRecords": [{"Value": "x.example.net"}]}}]})
    r53.change_tags_for_resource(ResourceType="hostedzone", ResourceId=ids["zone"],
                                 AddTags=[{"Key": "env", "Value": "prod"}])
    r53.create_health_check(CallerReference="h1", HealthCheckConfig={"IPAddress": "1.2.3.4", "Port": 80, "Type": "HTTP"})

    ec2 = c("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    subnets = [s["SubnetId"] for s in ec2.describe_subnets()["Subnets"][:2]]
    sg = ec2.create_security_group(GroupName="alb", Description="d", VpcId=vpc)["GroupId"]
    elb = c("elbv2")
    ids["lb"] = elb.create_load_balancer(Name="alb1", Subnets=subnets, SecurityGroups=[sg], Scheme="internet-facing",
                                         Tags=[{"Key": "app", "Value": "web"}])["LoadBalancers"][0]["LoadBalancerArn"]
    ids["tg"] = elb.create_target_group(Name="tg1", Protocol="HTTP", Port=80, VpcId=vpc)["TargetGroups"][0]["TargetGroupArn"]
    ids["listener"] = elb.create_listener(
        LoadBalancerArn=ids["lb"], Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": ids["tg"]}])["Listeners"][0]["ListenerArn"]
    elb.create_rule(ListenerArn=ids["listener"], Priority=10,
                    Conditions=[{"Field": "host-header", "Values": ["a.example.com"]}],
                    Actions=[{"Type": "forward", "ForwardConfig": {"TargetGroups": [
                        {"TargetGroupArn": ids["tg"], "Weight": 5}]}}])
    c("elb").create_load_balancer(LoadBalancerName="classic1", AvailabilityZones=[R + "a"],
                                  Listeners=[{"Protocol": "http", "LoadBalancerPort": 80, "InstancePort": 80}])

    waf = c("wafv2")
    ids["ipset"] = waf.create_ip_set(Name="ips1", Scope="REGIONAL", IPAddressVersion="IPV4",
                                     Addresses=["10.0.0.0/8", "203.0.113.5/32"])["Summary"]["ARN"]
    rule = {"Name": "block-ips", "Priority": 1, "Action": {"Block": {}}, "VisibilityConfig": VIS,
            "Statement": {"NotStatement": {"Statement": {"IPSetReferenceStatement": {"ARN": ids["ipset"]}}}}}
    ids["acl"] = waf.create_web_acl(Name="acl1", Scope="REGIONAL", DefaultAction={"Allow": {}}, Rules=[rule],
                                    VisibilityConfig=VIS)["Summary"]["ARN"]
    waf.create_web_acl(Name="cfacl", Scope="CLOUDFRONT", DefaultAction={"Allow": {}}, VisibilityConfig=VIS)
    waf.create_ip_set(Name="cfips", Scope="CLOUDFRONT", IPAddressVersion="IPV4", Addresses=["198.51.100.0/24"])
    c("acm").request_certificate(DomainName="example.com", SubjectAlternativeNames=["www.example.com"])

    asg = c("autoscaling")
    asg.create_launch_configuration(LaunchConfigurationName="lc1", ImageId="ami-12c6146b", InstanceType="t2.micro",
                                    UserData="export DB_PASSWORD=hunter2hunter2")
    asg.create_auto_scaling_group(AutoScalingGroupName="asg1", LaunchConfigurationName="lc1", MinSize=0, MaxSize=1,
                                  AvailabilityZones=[R + "a"])
    c("cloudfront").create_distribution(DistributionConfig={
        "CallerReference": "c1", "Comment": "d", "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{"Id": "o1", "DomainName": "alb1.example.com", "CustomOriginConfig": {
            "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "http-only"}}]},
        "DefaultCacheBehavior": {"TargetOriginId": "o1", "ViewerProtocolPolicy": "allow-all", "MinTTL": 0,
                                 "ForwardedValues": {"QueryString": False, "Cookies": {"Forward": "none"}}},
        "Aliases": {"Quantity": 1, "Items": ["cdn.example.com"]}})
    return ids


def make_env():
    settings = Settings(accounts=[AccountSettings(account_id="123456789012", regions=[R])])
    return settings, load_spec(SPEC), Store(mongomock.MongoClient()["cspm"], MongoSettings())


def scan(env, services=FLOW, **kw):
    settings, spec, store = env
    return run_scan(settings, spec, store, flt=ScanFilter(services=set(services)), **kw)


def one(store, service, rtype, **extra):
    return store.db.resources.find_one({"service": service, "resource_type": rtype, **extra})


def row(store, scan_id, service, api):
    return store.db.collection_status.find_one({"scan_id": scan_id, "service": service, "api": api})
