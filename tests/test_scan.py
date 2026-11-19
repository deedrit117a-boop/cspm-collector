"""End-to-end: moto AWS -> collectors -> mongomock store."""
import json
from pathlib import Path
from unittest import mock

import boto3
import mongomock
import pytest
from moto import mock_aws

from cspm_collector.collectors.base import CollectOptions
from cspm_collector.core.call import CallResult
from cspm_collector.core.config import AccountSettings, MongoSettings, Settings
from cspm_collector.core.errors import Status
from cspm_collector.core.scan import ScanFilter, run_scan
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
ACCOUNT = "123456789012"
REGION = "us-east-1"


@pytest.fixture
def env():
    with mock_aws():
        settings = Settings(accounts=[AccountSettings(account_id=ACCOUNT, regions=[REGION])])
        store = Store(mongomock.MongoClient()["cspm"], MongoSettings())
        yield settings, load_spec(SPEC), store


def scan(env, services, **kw):
    settings, spec, store = env
    kw.setdefault("options", CollectOptions(poll_interval=0))
    return run_scan(settings, spec, store, flt=ScanFilter(services=set(services.split(","))), **kw)


def resources(store, service, rtype=None, **extra):
    q = {"service": service, **({"resource_type": rtype} if rtype else {}), **extra}
    return list(store.db.resources.find(q))


def status_rows(store, scan_id, **q):
    return {(r["service"], r["api"]): r for r in store.db.collection_status.find({"scan_id": scan_id, **q})}


def test_spec_enables_the_vertical_slice():
    spec = load_spec(SPEC)
    assert {"ec2", "iam", "s3"} <= {s.service for s in spec.services if s.enabled}


# ----------------------------------------------------------------------------- EC2
def _ec2_fixture():
    ec2 = boto3.client("ec2", region_name=REGION)
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    sg = ec2.create_security_group(GroupName="web", Description="web sg")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SecurityGroupIds=[sg],
                      TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-1"}]}],
                      UserData="export DB_PASSWORD=hunter2hunter2\n")
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1)
    ec2.create_key_pair(KeyName="tmpkey")
    return sg, "tmpkey"


def test_ec2_collects_resources_status_and_settings(env):
    sg, _ = _ec2_fixture()
    s = scan(env, "ec2")
    store = env[2]

    types = {r["resource_type"] for r in resources(store, "ec2")}
    assert {"instance", "security_group", "network_interface", "volume"} <= types
    group = next(r for r in resources(store, "ec2", "security_group") if r["resource_id"] == sg)
    assert group["region"] == REGION and group["config"]["GroupName"] == "web"
    assert group["config"]["IpPermissions"][0]["IpRanges"][0]["CidrIp"] == "0.0.0.0/0"

    inst = resources(store, "ec2", "instance")[0]
    assert inst["tags"] == [{"key": "Name", "value": "web-1"}]
    eni = resources(store, "ec2", "network_interface")[0]["config"]
    assert {"Groups", "Attachment", "PrivateIpAddresses", "Description", "InterfaceType"} <= set(eni)

    rows = status_rows(store, s.scan_id)
    assert rows[("ec2", "describe_security_groups")]["status"] == "SUCCESS"
    assert rows[("ec2", "describe_launch_templates")]["status"] == "SUCCESS"
    assert rows[("ec2", "describe_launch_templates")]["resource_count"] == 0  # "none found" is a recorded SUCCESS
    attr = rows[("ec2", "describe_instance_attribute")]
    assert attr["status"] == "SKIPPED" and "--collect-userdata" in attr["error"]
    assert not attr["affects_sweep"]

    settings = {d["setting"] for d in store.db.account_settings.find({"scan_id": s.scan_id})}
    assert "ebs_encryption_by_default" in settings
    # moto does not implement several get_*_state calls: they must surface as rows, not crash the scan
    assert rows[("ec2", "get_serial_console_access_status")]["status"] == "ERROR"
    assert s.status == "PARTIAL"


def test_userdata_is_masked_and_never_stored(env):
    _ec2_fixture()
    s = scan(env, "ec2", options=CollectOptions(flags=frozenset({"--collect-userdata"}), poll_interval=0))
    store = env[2]
    inst = resources(store, "ec2", "instance")[0]
    assert inst["config"]["_details"]["describe_instance_attribute"]["UserData"]["Value"] == "***MASKED***"
    assert any(f["type"] == "password_assignment" for f in inst["secret_findings"])
    blob = json.dumps([d for c in store.db.list_collection_names() for d in store.db[c].find({})], default=str)
    assert "hunter2" not in blob
    assert status_rows(store, s.scan_id)[("ec2", "describe_instance_attribute")]["status"] == "SUCCESS"


def test_rescan_unchanged_then_change_then_delete(env):
    sg, key = _ec2_fixture()
    store = env[2]
    first = scan(env, "ec2")
    assert first.resources.inserted > 0 and first.resources.unchanged == 0

    second = scan(env, "ec2")
    assert (second.resources.inserted, second.resources.updated, second.resources.history) == (0, 0, 0)
    assert second.resources.unchanged == first.resources.inserted

    ec2 = boto3.client("ec2", region_name=REGION)
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    third = scan(env, "ec2")
    changed = store.db.resource_history.find_one({"resource_id": sg, "resource_type": "security_group"})
    assert third.resources.history >= 1 and changed is not None

    ec2.delete_key_pair(KeyName=key)
    fourth = scan(env, "ec2")
    assert fourth.swept >= 1
    assert store.db.resources.find_one({"resource_type": "key_pair"})["deleted_at"] is not None


def test_failed_collection_never_deletes(env):
    _, key = _ec2_fixture()
    store = env[2]
    scan(env, "ec2")
    from cspm_collector.collectors import generic

    real = generic.call_api

    def denied(client, service, api, *a, **kw):
        if api == "describe_key_pairs":
            return CallResult(Status.ACCESS_DENIED, error_code="UnauthorizedOperation")
        return real(client, service, api, *a, **kw)

    boto3.client("ec2", region_name=REGION).delete_key_pair(KeyName=key)
    with mock.patch.object(generic, "call_api", denied):
        s = scan(env, "ec2")
    assert s.status == "PARTIAL"
    gone = store.db.resources.find_one({"resource_type": "key_pair"})
    assert gone.get("deleted_at") is None  # describe_key_pairs failed: absence proves nothing
    assert status_rows(store, s.scan_id)[("ec2", "describe_key_pairs")]["status"] == "ACCESS_DENIED"
    sg_swept = [r for r in resources(store, "ec2", "security_group") if r.get("deleted_at")]
    assert sg_swept == []  # the other types were fully read and still exist


# ----------------------------------------------------------------------------- S3
def test_s3_regions_missing_configs_and_details(env):
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="alpha-bucket")
    s3.put_bucket_policy(Bucket="alpha-bucket", Policy=json.dumps({"Version": "2012-10-17", "Statement": []}))
    s3.put_bucket_tagging(Bucket="alpha-bucket", Tagging={"TagSet": [{"Key": "team", "Value": "sec"}]})
    eu = boto3.client("s3", region_name="eu-west-1")
    eu.create_bucket(Bucket="beta-bucket", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})

    s = scan(env, "s3")
    store = env[2]
    buckets = {r["resource_id"]: r for r in resources(store, "s3", "bucket")}
    assert set(buckets) == {"alpha-bucket", "beta-bucket"}
    a, b = buckets["alpha-bucket"], buckets["beta-bucket"]
    assert a["region"] == b["region"] == "global"
    assert a["resource_region"] == "us-east-1" and b["resource_region"] == "eu-west-1"
    assert a["arn"] == "arn:aws:s3:::alpha-bucket"
    assert a["tags"] == [{"key": "team", "value": "sec"}]
    assert a["config"]["_details"]["get_bucket_policy"]["Policy"]
    assert "get_bucket_policy" in b["config"]["_details"] and b["config"]["_details"]["get_bucket_policy"] is None
    assert "_errors" not in b["config"]  # "no such policy" is not an error

    rows = status_rows(store, s.scan_id)
    assert rows[("s3", "get_bucket_policy")]["status"] == "SUCCESS"
    assert rows[("s3", "get_bucket_policy")]["resource_count"] == 1  # only alpha had a policy
    assert rows[("s3", "list_buckets")]["resource_count"] == 2
    assert rows[("s3", "get_bucket_location")]["affects_sweep"] is False


# ----------------------------------------------------------------------------- IAM
def test_iam_users_roles_inline_policies_and_credential_report(env):
    iam = boto3.client("iam", region_name=REGION)
    iam.create_user(UserName="alice", Tags=[{"Key": "dept", "Value": "sec"}])
    key = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
    inline = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    iam.put_user_policy(UserName="alice", PolicyName="admin-ish", PolicyDocument=json.dumps(inline))
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                                                     "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps(trust))
    iam.create_policy(PolicyName="custom", PolicyDocument=json.dumps(inline))

    s = scan(env, "iam")
    store = env[2]
    user = resources(store, "iam", "user")[0]
    assert user["resource_id"] == "alice" and user["region"] == "global"
    d = user["config"]["_details"]
    assert d["list_access_keys"]["AccessKeyMetadata"][0]["AccessKeyId"] == key
    assert key in d["get_access_key_last_used"]
    assert d["get_user_policy"]["admin-ish"]["PolicyDocument"]["Statement"][0]["Action"] == "*"
    assert user["tags"] == [{"key": "dept", "value": "sec"}]

    role = resources(store, "iam", "role")[0]
    assert role["config"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["Service"] == "ec2.amazonaws.com"
    policy = resources(store, "iam", "policy")[0]
    assert policy["config"]["_details"]["get_policy_version"]["PolicyVersion"]["Document"]["Statement"]

    report = {r["resource_id"]: r for r in resources(store, "iam", "credential_report_row")}
    assert "alice" in report
    assert report["alice"]["config"]["user"] == "alice"

    settings = {d["setting"]: d["value"] for d in store.db.account_settings.find({"scan_id": s.scan_id})}
    assert settings["iam_account_summary"]["SummaryMap"]["Users"] >= 1
    assert settings["iam_password_policy"] is None  # none configured: recorded, not an error

    rows = status_rows(store, s.scan_id)
    assert rows[("iam", "get_login_profile")]["status"] == "SUCCESS"  # NoSuchEntity is "no config"
    assert rows[("iam", "get_credential_report")]["resource_count"] >= 1
    assert rows[("iam", "get_user_policy")]["status"] == "SUCCESS"


def test_service_failure_is_isolated(env):
    """A crashing collector yields an ERROR row and does not stop other services."""
    _ec2_fixture()
    boto3.client("iam", region_name=REGION).create_user(UserName="bob")
    from cspm_collector.collectors import ec2 as ec2_mod

    with mock.patch.object(ec2_mod.Ec2Collector, "collect", side_effect=RuntimeError("boom")):
        s = scan(env, "ec2,iam")
    store = env[2]
    assert s.status == "PARTIAL"
    assert store.db.collection_status.find_one({"scan_id": s.scan_id, "service": "ec2", "status": "ERROR"})
    assert resources(store, "iam", "credential_report_row")
