import json
import re
from pathlib import Path

import pytest

from cspm_collector.spec.iam_policy import (
    HELPER_CALLS,
    READ_VERBS,
    action_for,
    collect_actions,
    policy_documents,
)
from cspm_collector.spec.loader import load_spec
from cspm_collector.spec.schema import ApiSpec, CollectSpec, ServiceSpec

ROOT = Path(__file__).resolve().parents[1]
SPEC = load_spec(ROOT / "spec" / "collect_spec.yaml")


def _spec(client, *apis):
    return CollectSpec(spec_version="t", services=[ServiceSpec(service=client, client=client, apis=list(apis))])


def test_every_enabled_api_has_its_action():
    actions = set(collect_actions(SPEC))
    for svc in SPEC.services:
        if svc.enabled:
            for a in svc.apis:
                assert action_for(a.client or svc.client, a.api) in actions, (svc.service, a.api)


def test_actions_are_read_only_and_never_grant_data_access():
    actions = set(collect_actions(SPEC))
    assert all(a.split(":", 1)[1].startswith(READ_VERBS) or a == "apigateway:GET" for a in actions)
    forbidden = {"s3:GetObject", "s3:ListBucket", "secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters",
                 "kms:Decrypt", "lambda:InvokeFunction", "dynamodb:GetItem", "dynamodb:Scan", "sqs:ReceiveMessage",
                 "athena:GetQueryResults", "logs:GetLogEvents", "logs:FilterLogEvents", "cloudtrail:LookupEvents"}
    assert not (actions & forbidden)


def test_iam_names_that_differ_from_the_api_name():
    assert action_for("s3", "list_buckets") == "s3:ListAllMyBuckets"
    assert action_for("s3", "get_bucket_encryption") == "s3:GetEncryptionConfiguration"
    assert action_for("s3", "get_public_access_block") == "s3:GetBucketPublicAccessBlock"
    assert action_for("s3control", "get_public_access_block") == "s3:GetAccountPublicAccessBlock"
    assert action_for("apigatewayv2", "get_apis") == "apigateway:GET"
    assert action_for("docdb", "describe_db_clusters") == "rds:DescribeDBClusters"
    assert action_for("elbv2", "describe_rules") == "elasticloadbalancing:DescribeRules"
    assert action_for("efs", "describe_file_systems") == "elasticfilesystem:DescribeFileSystems"
    assert action_for("bedrock-agent", "list_agents") == "bedrock:ListAgents"
    assert action_for("sesv2", "get_account") == "ses:GetAccount"
    assert action_for("macie2", "get_macie_session") == "macie2:GetMacieSession"
    # services whose IAM prefix is not the boto3 client name
    assert action_for("stepfunctions", "list_state_machines") == "states:ListStateMachines"
    assert action_for("opensearch", "describe_domain") == "es:DescribeDomain"
    assert action_for("emr", "list_clusters") == "elasticmapreduce:ListClusters"
    assert action_for("resourcegroupstaggingapi", "get_resources") == "tag:GetResources"


def test_a_mutating_api_in_the_spec_is_refused():
    with pytest.raises(ValueError, match="non read-only"):
        collect_actions(_spec("s3", ApiSpec(api="delete_bucket")))


def test_documents_respect_the_managed_policy_size_limit():
    docs = policy_documents(SPEC)
    assert len(docs) >= 2
    for doc in docs:
        assert len(re.sub(r"\s", "", json.dumps(doc))) <= 6144
        stmt = doc["Statement"][0]
        assert doc["Version"] == "2012-10-17" and stmt["Effect"] == "Allow" and stmt["Resource"] == "*"
        assert stmt["Action"] == sorted(set(stmt["Action"]))
    merged = [a for d in docs for a in d["Statement"][0]["Action"]]
    assert merged == collect_actions(SPEC) and len(set(merged)) == len(merged)


def test_disabled_services_are_left_out_unless_asked():
    assert "tag:GetResources" not in collect_actions(SPEC)
    assert "tag:GetResources" in collect_actions(SPEC, enabled_only=False)


def test_helper_calls_in_collectors_are_all_covered():
    """Collectors call some APIs themselves (self.call("name", ...)); their permissions must be in the policy."""
    spec_apis = {a.api for s in SPEC.services for a in s.apis}
    helper_apis = {api for _, api in HELPER_CALLS}
    found = set()
    for path in (ROOT / "src" / "cspm_collector" / "collectors").glob("*.py"):
        found |= set(re.findall(r'self\.call\(\s*"(\w+)"', path.read_text(encoding="utf-8")))
    assert found, "pattern matched nothing: the test would pass vacuously"
    assert found <= spec_apis | helper_apis, sorted(found - spec_apis - helper_apis)


def test_committed_policy_files_match_the_spec():
    files = sorted((ROOT / "iam").glob("policy-*.json"))
    committed = [a for f in files for a in json.loads(f.read_text(encoding="utf-8"))["Statement"][0]["Action"]]
    assert committed == collect_actions(SPEC), "run `collect iam-policy` again (the spec changed)"
