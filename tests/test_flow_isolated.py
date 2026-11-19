"""Flow-chart tests that need a pristine moto world (kept in their own module: a module-scoped world
elsewhere would otherwise still be active and make names collide)."""
from unittest import mock

import boto3
from moto import mock_aws

from cspm_collector.collectors.base import CollectOptions
from cspm_collector.core.call import CallResult, call_api
from cspm_collector.core.errors import Status

from flow_helpers import R, VIS, build_world, make_env, one, scan


def test_userdata_scan_flag_reports_type_only():
    with mock_aws():
        asg = boto3.client("autoscaling", region_name=R)
        asg.create_launch_configuration(LaunchConfigurationName="lc1", ImageId="ami-12c6146b", InstanceType="t2.micro",
                                        UserData="export DB_PASSWORD=hunter2hunter2")
        env = make_env()
        scan(env, {"autoscaling"}, options=CollectOptions(flags=frozenset({"--collect-userdata"})))
        lc = one(env[2], "autoscaling", "launch_configuration")
        assert lc["secret_findings"] == [{"location": "launch_configuration.lc1.UserData", "type": "password_assignment",
                                          "line": 1}]


def test_failed_record_listing_never_deletes_records():
    with mock_aws():
        ids = build_world()
        env = make_env()
        scan(env, {"route53"})
        store = env[2]
        r53 = boto3.client("route53", region_name=R)
        r53.change_resource_record_sets(HostedZoneId=ids["zone"], ChangeBatch={"Changes": [
            {"Action": "DELETE", "ResourceRecordSet": {"Name": "old.example.com.", "Type": "CNAME", "TTL": 60,
                                                        "ResourceRecords": [{"Value": "x.example.net"}]}}]})
        from cspm_collector.collectors import generic

        real = generic.call_api

        def denied(client, service, api, *a, **kw):
            if api == "list_resource_record_sets":
                return CallResult(Status.ACCESS_DENIED, error_code="AccessDenied")
            return real(client, service, api, *a, **kw)

        with mock.patch.object(generic, "call_api", denied):
            failed = scan(env, {"route53"})
        old = one(store, "route53", "record_set", resource_id=f"{ids['zone']}|old.example.com.|CNAME")
        assert failed.status == "PARTIAL" and old.get("deleted_at") is None  # absence proves nothing when listing failed

        scan(env, {"route53"})  # listing works again: now the record really is gone
        assert one(store, "route53", "record_set", resource_id=f"{ids['zone']}|old.example.com.|CNAME")["deleted_at"]


def test_manual_pagination_uses_the_request_parameter_the_api_expects():
    """WAF responds with NextMarker and wants NextMarker back (most APIs want Marker)."""
    with mock_aws():
        waf = boto3.client("wafv2", region_name=R)
        for i in range(3):
            waf.create_web_acl(Name=f"acl{i}", Scope="REGIONAL", DefaultAction={"Allow": {}}, VisibilityConfig=VIS)
        res = call_api(waf, "wafv2", "list_web_acls", {"Scope": "REGIONAL", "Limit": 1}, paginate=False)
        assert res.ok and res.api_calls >= 3
        assert sorted(a["Name"] for p in res.pages for a in p["WebACLs"]) == ["acl0", "acl1", "acl2"]
