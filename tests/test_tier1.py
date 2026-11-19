"""Tier 1 services end to end on moto: one shared world, one scan, many assertions."""
import io
import json
import os
import zipfile
from pathlib import Path

import boto3
import mongomock
import pytest
from moto import mock_aws

from cspm_collector.collectors.base import CollectOptions
from cspm_collector.core.config import AccountSettings, MongoSettings, Settings
from cspm_collector.core.scan import ScanFilter, run_scan
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
R = "us-east-1"
SKIPPED_HERE = {"ec2", "iam"}  # covered by test_scan.py (ec2 is slow under moto)


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("l.py", "def h(e, c):\n    return 1\n")
    return buf.getvalue()


@pytest.fixture(scope="module")
def world():
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": R}.items():
        os.environ.setdefault(k, v)
    with mock_aws():
        c = lambda name: boto3.client(name, region_name=R)  # noqa: E731
        c("s3").create_bucket(Bucket="trail-bucket")
        c("s3control").put_public_access_block(AccountId="123456789012", PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        c("cloudtrail").create_trail(Name="trail1", S3BucketName="trail-bucket", IsMultiRegionTrail=True)
        c("cloudwatch").put_metric_alarm(
            AlarmName="alarm1", MetricName="m", Namespace="n", Statistic="Sum", Period=60, EvaluationPeriods=1,
            Threshold=1, ComparisonOperator="GreaterThanThreshold")
        c("logs").create_log_group(logGroupName="lg1")
        c("logs").put_metric_filter(
            logGroupName="lg1", filterName="f1", filterPattern="x",
            metricTransformations=[{"metricName": "m", "metricNamespace": "n", "metricValue": "1"}])
        key_id = c("kms").create_key(Description="k", Tags=[{"TagKey": "owner", "TagValue": "sec"}])["KeyMetadata"]["KeyId"]
        topic = c("sns").create_topic(Name="topic1", Tags=[{"Key": "env", "Value": "prod"}])["TopicArn"]
        c("sqs").create_queue(QueueName="q1", tags={"team": "net"})
        role = c("iam").create_role(RoleName="lambda-role", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
        c("lambda").create_function(FunctionName="fn1", Runtime="python3.12", Role=role, Handler="l.h",
                                    Code={"ZipFile": _zip()},
                                    Environment={"Variables": {"DB_PASSWORD": "hunter2hunter2", "MODE": "prod"}})
        c("secretsmanager").create_secret(Name="sec1", SecretString="topsecretvalue")
        c("events").put_rule(Name="rule1", ScheduleExpression="rate(5 minutes)")
        c("efs").create_file_system(CreationToken="fs1")
        c("apigateway").create_rest_api(name="api1")
        c("apigatewayv2").create_api(Name="api2", ProtocolType="HTTP")
        c("guardduty").create_detector(Enable=True)
        c("organizations").create_organization(FeatureSet="ALL")
        c("config").put_configuration_recorder(ConfigurationRecorder={"name": "default", "roleARN": role})

        settings = Settings(accounts=[AccountSettings(account_id="123456789012", regions=[R])])
        store = Store(mongomock.MongoClient()["cspm"], MongoSettings())
        spec = load_spec(SPEC)
        names = {s.service for s in spec.services if s.enabled} - SKIPPED_HERE
        summary = run_scan(settings, spec, store, flt=ScanFilter(services=names),
                           options=CollectOptions(poll_interval=0))
        yield {"store": store, "summary": summary, "spec": spec, "key_id": key_id, "topic": topic, "role": role}


def one(world, service, rtype, rid=None):
    q = {"service": service, "resource_type": rtype, **({"resource_id": rid} if rid else {})}
    return world["store"].db.resources.find_one(q)


def row(world, service, api):
    return world["store"].db.collection_status.find_one(
        {"scan_id": world["summary"].scan_id, "service": service, "api": api})


def setting(world, name):
    d = world["store"].db.account_settings.find_one({"scan_id": world["summary"].scan_id, "setting": name})
    return d["value"] if d else "<missing>"


def test_tier1_services_are_enabled_and_valid():
    spec = load_spec(SPEC)
    enabled = {s.service for s in spec.services if s.enabled}
    assert enabled >= {"ec2", "iam", "s3"} | {"vpc", "cloudtrail", "cloudwatch", "rds", "kms", "account", "accessanalyzer", "config",
                               "securityhub", "macie", "guardduty", "inspector2", "organizations", "awslambda",
                               "apigateway", "apigatewayv2", "efs", "glacier", "sns", "sqs", "secretsmanager",
                               "eventbridge"}


def test_every_enabled_service_leaves_status_rows(world):
    seen = set(world["store"].db.collection_status.distinct("service", {"scan_id": world["summary"].scan_id}))
    expected = {s.service for s in world["spec"].services if s.enabled} - SKIPPED_HERE
    assert expected <= seen
    assert world["summary"].status in ("COMPLETED", "PARTIAL")


def test_cloudtrail_home_region_trail_with_list_wrapped_param(world):
    t = one(world, "cloudtrail", "trail")
    assert t["resource_id"].endswith("trail/trail1") and t["arn"] == t["resource_id"]
    assert t["config"]["IsMultiRegionTrail"] is True
    d = t["config"]["_details"]
    assert "get_trail_status" in d and "get_event_selectors" in d
    assert row(world, "cloudtrail", "list_tags")["status"] == "SUCCESS"  # "ResourceIdList[]" wrapped into a list


def test_cloudwatch_alarm_metric_filter_and_log_group(world):
    a = one(world, "cloudwatch", "alarm", "alarm1")
    assert a["arn"].endswith(":alarm:alarm1")
    mf = one(world, "cloudwatch", "metric_filter")
    assert mf["resource_id"] == "lg1|f1"  # composite id: filter names are only unique per log group
    assert one(world, "cloudwatch", "log_group", "lg1")["config"]["logGroupName"] == "lg1"


def test_kms_details_and_tag_key_value_style(world):
    k = one(world, "kms", "key", world["key_id"])
    assert {"describe_key", "get_key_rotation_status", "get_key_policy"} <= set(k["config"]["_details"])
    assert k["tags"] == [{"key": "owner", "value": "sec"}]
    assert k["arn"].endswith(world["key_id"])


def test_sns_and_sqs_arn_and_tags(world):
    t = one(world, "sns", "topic", world["topic"])
    assert t["arn"] == world["topic"] and t["tags"] == [{"key": "env", "value": "prod"}]
    assert "get_topic_attributes" in t["config"]["_details"]
    q = one(world, "sqs", "queue")
    assert q["resource_id"].endswith("/q1") and q["arn"].endswith(":q1")  # bare URL wrapped, ARN from attributes
    assert q["tags"] == [{"key": "team", "value": "net"}]


def test_lambda_env_masked_and_secrets_never_stored(world):
    f = one(world, "awslambda", "function", "fn1")
    assert f["config"]["Environment"]["Variables"] == {"DB_PASSWORD": "***MASKED***", "MODE": "***MASKED***"}
    assert [x["type"] for x in f["secret_findings"]] == ["password_assignment"]
    assert f["secret_findings"][0]["location"] == "lambda.fn1.Environment.DB_PASSWORD"
    store = world["store"]
    blob = json.dumps([d for c in store.db.list_collection_names() for d in store.db[c].find({})], default=str)
    assert "hunter2" not in blob
    assert "topsecretvalue" not in blob  # secretsmanager: the value is never even requested
    assert "Location" not in json.dumps(f["config"]["_details"].get("get_function", {}).get("Code", {})) or \
        f["config"]["_details"]["get_function"]["Code"]["Location"] == "***MASKED***"


def test_secretsmanager_metadata_only(world):
    s = one(world, "secretsmanager", "secret", "sec1")
    assert s["arn"].startswith("arn:aws:secretsmanager:") and "describe_secret" in s["config"]["_details"]


def test_eventbridge_efs_apigateway(world):
    bus = one(world, "eventbridge", "event_bus", "default")
    assert [r["Name"] for r in bus["config"]["_details"]["list_rules"]["Rules"]] == ["rule1"]
    assert one(world, "efs", "file_system")["config"]["FileSystemId"].startswith("fs-")
    assert row(world, "efs", "describe_file_system_policy")["status"] == "SUCCESS"  # PolicyNotFound = no policy
    api = one(world, "apigateway", "rest_api")
    assert api["config"]["name"] == "api1" and "get_stages" in api["config"]["_details"]
    assert one(world, "apigatewayv2", "api")["config"]["Name"] == "api2"


def test_vpc_has_default_network(world):
    assert one(world, "vpc", "vpc")["config"]["IsDefault"] is True
    assert one(world, "vpc", "subnet") and one(world, "vpc", "route_table")


def test_enablement_settings_per_region(world):
    assert setting(world, "guardduty_enablement") == {"enabled": True, "status": "SUCCESS", "resources": 1}
    assert setting(world, "config_enablement")["enabled"] is True
    # moto: Security Hub not subscribed -> NOT_ENABLED row and enabled=False, not an error
    assert row(world, "securityhub", "describe_hub")["status"] == "NOT_ENABLED"
    assert setting(world, "securityhub_enablement") == {"enabled": False, "status": "NOT_ENABLED", "resources": 0}
    # a probe that could not answer is "unknown", never "disabled"
    assert setting(world, "accessanalyzer_enablement")["enabled"] is None


def test_guardduty_scalar_ids_become_resources(world):
    d = one(world, "guardduty", "detector")
    assert len(d["resource_id"]) >= 8 and "get_detector" in d["config"]["_details"]


def test_organizations_policy_types_use_aliases(world):
    keys = {r["api"] for r in world["store"].db.collection_status.find(
        {"scan_id": world["summary"].scan_id, "service": "organizations"})}
    assert {"list_policies_scp", "list_policies_tag", "list_policies_backup", "list_policies_ai_optout"} <= keys
    assert one(world, "organizations", "account") and one(world, "organizations", "organization_policy")
    assert setting(world, "organizations_organization")["Organization"]["FeatureSet"] == "ALL"


def test_account_settings_include_s3control_and_contacts(world):
    pab = setting(world, "s3_account_public_access_block")
    assert pab["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] is True
    assert row(world, "s3", "s3control_account_public_access_block")["status"] == "SUCCESS"
    # no alternate contact registered: recorded as None (a finding for the rules), not an error
    for kind in ("billing", "operations", "security"):
        assert setting(world, f"account_alternate_contact_{kind}") is None


def test_macie_not_enabled_message_is_not_access_denied():
    from botocore.exceptions import ClientError

    from cspm_collector.core.errors import Status, classify_exception

    err = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "Macie is not enabled"}}, "GetMacieSession")
    assert classify_exception(err, "macie").status is Status.NOT_ENABLED
    assert classify_exception(err, "s3").status is Status.ACCESS_DENIED  # only macie gets the override


def test_rds_instances_snapshots_and_parameter_groups():
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing"}.items():
        os.environ.setdefault(k, v)
    with mock_aws():
        rds = boto3.client("rds", region_name=R)
        rds.create_db_parameter_group(DBParameterGroupName="pg1", DBParameterGroupFamily="postgres15", Description="d")
        rds.create_db_instance(DBInstanceIdentifier="db1", DBInstanceClass="db.t3.micro", Engine="postgres",
                               MasterUsername="admin", MasterUserPassword="Passw0rd-Xyz123", AllocatedStorage=20,
                               DBParameterGroupName="pg1", Tags=[{"Key": "env", "Value": "prod"}])
        rds.create_db_snapshot(DBInstanceIdentifier="db1", DBSnapshotIdentifier="snap1")
        settings = Settings(accounts=[AccountSettings(account_id="123456789012", regions=[R])])
        store = Store(mongomock.MongoClient()["cspm"], MongoSettings())
        s = run_scan(settings, load_spec(SPEC), store, flt=ScanFilter(services={"rds"}))
        world = {"store": store, "summary": s}

        db = one(world, "rds", "db_instance", "db1")
        assert db["arn"].endswith(":db:db1") and db["tags"] == [{"key": "env", "value": "prod"}]
        assert "MasterUserPassword" not in json.dumps(db["config"])
        snap = one(world, "rds", "db_snapshot", "snap1")
        assert "describe_db_snapshot_attributes" in snap["config"]["_details"]
        assert one(world, "rds", "db_parameter_group", "pg1")
        assert row(world, "rds", "describe_db_instances")["status"] == "SUCCESS"
