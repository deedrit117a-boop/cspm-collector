"""Smaller gaps: credential refresh, secret detection, stats, assemble, builder edge cases, EC2 masking."""
import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import boto3
import pytest
import yaml
from moto import mock_aws

from cspm_collector.collectors.base import CollectOptions
from cspm_collector.collectors.ec2 import SCAN_FLAG, Ec2Collector
from cspm_collector.collectors.generic import Entry
from cspm_collector.core.config import AccountSettings
from cspm_collector.core.secrets import MASK, mask_environment, mask_user_data, scan_text
from cspm_collector.core.session import AccountSession
from cspm_collector.core.stats import Stats
from cspm_collector.spec.assemble import assemble, load_overrides
from cspm_collector.spec.builder import build_spec
from cspm_collector.spec.schema import ApiSpec, CollectSpec, ServiceSpec

SECRET = "hunter2hunter2"


# ------------------------------------------------------------------------------ credentials
@mock_aws
def test_assumed_role_credentials_refresh_when_they_expire(monkeypatch):
    monkeypatch.setenv("CSPM_EXT", "ext-id")
    role = boto3.client("iam", region_name="us-east-1").create_role(
        RoleName="r", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    sess = AccountSession(AccountSettings(account_id="123456789012", role_arn=role, external_id_env="CSPM_EXT"))
    creds = sess._session.get_credentials()
    first = creds.get_frozen_credentials()
    assert first.access_key and first.token  # temporary credentials: they carry a session token
    assert sess.client("ec2").describe_regions()["Regions"]

    creds._expiry_time = datetime.now(timezone.utc) - timedelta(minutes=1)  # pretend the hour is over
    second = creds.get_frozen_credentials()
    assert second.access_key != first.access_key  # a fresh AssumeRole call happened by itself
    assert creds._expiry_time > datetime.now(timezone.utc)


# ------------------------------------------------------------------------------ secrets
@pytest.mark.parametrize("text,kind", [
    ("AKIAIOSFODNN7EXAMPLE", "aws_access_key_id"),
    ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
    ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_access_key"),
    ("DB_PASSWORD=hunter2", "password_assignment"),
    ("client_secret: abcdef", "secret_assignment"),
    ("postgres://admin:p4ss@db.internal:5432/app", "basic_auth_url"),
])
def test_secret_patterns(text, kind):
    assert kind in {f["type"] for f in scan_text(text)}


def test_ordinary_text_is_not_a_secret():
    assert scan_text("echo hello\nexport PATH=/usr/bin\nport=8080\nhttps://example.com/path") == []


def test_user_data_helpers():
    assert mask_user_data(None, True, "x") == (None, []) and mask_user_data("", True, "x") == ("", [])
    encoded = base64.b64encode(f"password={SECRET}".encode()).decode()
    assert mask_user_data(encoded, False, "i-1.UserData") == (MASK, [])  # not scanning: masked, no findings
    masked, findings = mask_user_data(encoded, True, "i-1.UserData")
    assert masked == MASK and findings == [{"location": "i-1.UserData", "type": "password_assignment", "line": 1}]
    assert mask_user_data(f"password={SECRET}", True, "x")[1]  # not base64: scanned as plain text
    assert mask_environment(None, "x") == (None, []) and mask_environment({}, "x") == ({}, [])
    env, hits = mask_environment({"TOKEN": SECRET}, "fn")
    assert env == {"TOKEN": MASK} and hits == [{"location": "fn.TOKEN", "type": "secret_assignment"}]


def test_ec2_user_data_masking_with_and_without_the_scan_flag():
    api_attr = ApiSpec(api="describe_instance_attribute")
    api_lt = ApiSpec(api="describe_launch_template_versions")
    payload = base64.b64encode(f"password={SECRET}".encode()).decode()

    def run(flags):
        c = Ec2Collector()
        c.ctx = SimpleNamespace(options=CollectOptions(flags=frozenset(flags)))
        entry = Entry(item={}, rid="i-1")
        attr = c.sanitize_detail(api_attr, {"UserData": {"Value": payload}}, entry)
        lt = c.sanitize_detail(api_lt, {"LaunchTemplateVersions": [{"LaunchTemplateData": {"UserData": payload}}]}, entry)
        assert c.sanitize_detail(api_attr, None, entry) is None
        assert c.tags_for(api_attr, Entry(item={"TagSet": [{"Key": "a", "Value": "b"}]}, rid="x")) == [{"Key": "a", "Value": "b"}]
        return attr, lt, entry.findings

    attr, lt, findings = run([SCAN_FLAG])
    assert attr["UserData"]["Value"] == MASK and lt["LaunchTemplateVersions"][0]["LaunchTemplateData"]["UserData"] == MASK
    assert {f["location"] for f in findings} == {"instance.i-1.UserData", "launch_template.i-1.versions[0].UserData"}
    attr, lt, findings = run([])
    assert attr["UserData"]["Value"] == MASK and findings == []


# ------------------------------------------------------------------------------ stats
def test_stats_summary_lists_the_slowest_first():
    s = Stats()
    s.record("s3", "list_buckets", 10)
    s.record("ec2", "describe_instances", 300)
    s.record("ec2", "describe_instances", 200, error=True)
    assert s.calls == 3 and s.errors == 1
    top = s.slowest(1)[0]
    assert (top["service"], top["api"], top["calls"], top["total_ms"]) == ("ec2", "describe_instances", 2, 500.0)
    text = s.summary(2)
    assert "total API calls: 3 (errors: 1)" in text and text.index("ec2.describe_instances") < text.index("s3.list_buckets")


# ------------------------------------------------------------------------------ assemble
def test_assemble_merges_overrides_and_disables_the_rest(tmp_path):
    generated = CollectSpec(spec_version="v1", services=[
        ServiceSpec(service="sqs", client="sqs", tier=2, rule_count=7, apis=[ApiSpec(api="list_queues")]),
        ServiceSpec(service="sns", client="sns", tier=1, rule_count=3, apis=[ApiSpec(api="list_topics")]),
    ])
    (tmp_path / "sqs.yaml").write_text(yaml.safe_dump({"service": "sqs", "client": "sqs", "collector": "sqs",
                                                       "apis": [{"api": "list_queues", "result_path": "QueueUrls"}]}), encoding="utf-8")
    (tmp_path / "new.yaml").write_text(yaml.safe_dump({"service": "newsvc", "client": "sns", "tier": 2, "apis": []}), encoding="utf-8")
    spec = assemble(generated, load_overrides(tmp_path))
    by = {s.service: s for s in spec.services}
    assert by["sqs"].enabled and by["sqs"].tier == 2 and by["sqs"].rule_count == 7  # generated metadata kept
    assert by["sqs"].apis[0].result_path == "QueueUrls" and by["sqs"].collector == "sqs"
    assert not by["sns"].enabled  # generated but never curated
    assert by["newsvc"].enabled and by["newsvc"].tier == 2  # a service Prowler never calls
    assert spec.spec_version == "v1"


def test_override_can_pin_its_own_tier(tmp_path):
    generated = CollectSpec(spec_version="v1", services=[ServiceSpec(service="a", client="sqs", tier=3)])
    (tmp_path / "a.yaml").write_text(yaml.safe_dump({"service": "a", "client": "sqs", "tier": 1}), encoding="utf-8")
    assert assemble(generated, load_overrides(tmp_path)).services[0].tier == 1


# ------------------------------------------------------------------------------ builder edge cases
def _tree(tmp_path, files):
    for name, src in files.items():
        d = tmp_path / "services" / name
        d.mkdir(parents=True)
        (d / f"{name}_service.py").write_text(src, encoding="utf-8")
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([{"check_id": "x", "service": "ghost"}]), encoding="utf-8")
    return tmp_path / "services", rules


def test_builder_reports_unresolved_apis_unknown_clients_and_missing_service_dirs(tmp_path):
    services, rules = _tree(tmp_path, {
        "iam": "def f(client):\n    client.list_users()\n    client.list_attached_user_policies(UserName='x')\n"
               "    client.get_totally_made_up()\n",
        "notaclient": "def f(client):\n    client.list_things()\n",
        "awslambda": "def f(client):\n    client.list_functions()\n",
    })
    spec, report = build_spec(services, rules)
    names = {s.service: s for s in spec.services}
    assert "notaclient" in report["services_without_client"] and "notaclient" not in names
    assert names["awslambda"].client == "lambda"  # prowler dir name differs from the boto3 client
    assert report["unresolved_apis"] == {"iam": ["get_totally_made_up"]}
    assert report["rules_without_service_dir"] == ["ghost"]
    apis = {a.api: a for a in names["iam"].apis}
    # list_users items carry UserName, so the per-user call is wired to it automatically
    assert apis["list_attached_user_policies"].depends_on.api == "list_users"
    assert apis["list_attached_user_policies"].depends_on.params == {"UserName": "UserName"}
    assert names["iam"].scope == "global" and names["iam"].collector == "iam"
    assert names["iam"].tier == 1 and names["awslambda"].tier == 1


# ------------------------------------------------------------------------------ TLS-inspecting proxies
def test_ca_bundle_contains_certifi_plus_system_roots(tmp_path):
    import certifi

    from cspm_collector.core.tls import build_ca_bundle

    out = tmp_path / "bundle.pem"
    base, extra = build_ca_bundle(out)
    text = out.read_text(encoding="ascii")
    assert base > 100 and text.count("BEGIN CERTIFICATE") == base + extra
    assert certifi.where() and open(certifi.where(), encoding="ascii").read().strip() in text
    import ssl

    ssl.create_default_context(cafile=str(out))  # a bundle OpenSSL can actually load


def test_waf_region_limitation_is_not_supported_not_error():
    from botocore.exceptions import ClientError

    from cspm_collector.core.errors import Status, classify_exception

    err = ClientError({"Error": {"Code": "WAFInvalidParameterException",
                                 "Message": "The resource is not supported in current region"}}, "ListResourcesForWebACL")
    assert classify_exception(err, "wafv2").status is Status.NOT_SUPPORTED
    other = ClientError({"Error": {"Code": "WAFInvalidParameterException", "Message": "bad ARN"}}, "GetWebACL")
    assert classify_exception(other, "wafv2").status is Status.ERROR  # only that message is a region limitation


def test_iam_actions_and_arns_are_not_secrets():
    for benign in ("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:prod/db-AbC123",
                   "ssm:GetParameter", "sts:GetSessionToken", "tokenizer:x", "password_policy", "kms:Decrypt"):
        assert scan_text(benign) == [], benign


@pytest.mark.parametrize("text", [
    "password=hunter2", "DB_PASSWORD: hunter2", 'password: "hunter2"', '{"api_key": "abcdef123456"}',
    "client_secret = abcdef", "token: abc", "export SECRET_KEY='abc'",
])
def test_real_assignments_are_still_found(text):
    assert scan_text(text), text


def test_glue_disabled_endpoint_is_not_a_permission_problem():
    from botocore.exceptions import ClientError

    from cspm_collector.core.errors import Status, classify_exception

    err = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "GetDevEndpoints operation is currently disabled."}}, "GetDevEndpoints")
    assert classify_exception(err, "glue").status is Status.NOT_SUPPORTED
    real = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "User is not authorized to perform glue:GetConnections"}}, "GetConnections")
    assert classify_exception(real, "glue").status is Status.ACCESS_DENIED


def test_fms_without_admin_and_uninitialized_drs_are_not_failures():
    from botocore.exceptions import ClientError

    from cspm_collector.core.errors import Status, classify_exception

    fms = ClientError({"Error": {"Code": "AccessDeniedException",
                                 "Message": "No default admin could be found for account 1 in Region us-east-1"}}, "ListPolicies")
    assert classify_exception(fms, "fms").status is Status.NOT_ENABLED
    drs = ClientError({"Error": {"Code": "UninitializedAccountException", "Message": "Account not initialized"}}, "DescribeJobs")
    assert classify_exception(drs, "drs").status is Status.NOT_ENABLED
