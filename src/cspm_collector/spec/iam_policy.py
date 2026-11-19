"""Least-privilege, read-only IAM policy derived from the collection spec.

Every API the spec (or a collector helper) calls becomes one explicit action. Wildcards such as ``s3:Get*`` are
deliberately avoided: they would also grant ``s3:GetObject``, ``secretsmanager:GetSecretValue`` and the like.
"""
from __future__ import annotations

import json

from . import botomodel
from .schema import CollectSpec

# boto3 client name -> IAM service prefix (only where they differ)
CLIENT_PREFIX = {
    "bedrock-agent": "bedrock",
    "docdb": "rds",
    "neptune": "rds",
    "elb": "elasticloadbalancing",
    "elbv2": "elasticloadbalancing",
    "efs": "elasticfilesystem",
    "s3control": "s3",
    "sesv2": "ses",
    "apigatewayv2": "apigateway",
    "emr": "elasticmapreduce",
    "opensearch": "es",
    "resourcegroupstaggingapi": "tag",
    "stepfunctions": "states",
}

# s3 operations whose IAM action has a different name
S3_ACTIONS = {
    ("s3", "list_buckets"): "ListAllMyBuckets",
    ("s3", "head_bucket"): "ListBucket",
    ("s3", "get_public_access_block"): "GetBucketPublicAccessBlock",
    ("s3control", "get_public_access_block"): "GetAccountPublicAccessBlock",
    ("s3", "get_bucket_encryption"): "GetEncryptionConfiguration",
    ("s3", "get_bucket_lifecycle_configuration"): "GetLifecycleConfiguration",
    ("s3", "get_object_lock_configuration"): "GetBucketObjectLockConfiguration",
    ("s3", "get_bucket_replication"): "GetReplicationConfiguration",
    ("s3", "get_bucket_notification_configuration"): "GetBucketNotification",
}

# Calls a collector makes on its own (not listed in the spec). tests/test_iam_policy.py keeps this complete.
HELPER_CALLS = [
    ("ec2", "describe_regions"),  # region discovery
    ("s3", "get_bucket_location"),
    ("iam", "get_access_key_last_used"), ("iam", "get_user_policy"), ("iam", "get_role_policy"),
    ("iam", "get_group_policy"),
    ("route53", "list_tags_for_resource"),
    ("ecs", "list_services"), ("ecs", "describe_services"), ("ecs", "list_tasks"), ("ecs", "describe_tasks"),
    ("ecs", "list_container_instances"), ("ecs", "describe_container_instances"),
    ("eks", "list_nodegroups"), ("eks", "describe_nodegroup"),
    ("dynamodb", "list_tags_of_resource"), ("dynamodb", "get_resource_policy"),
    ("opensearch", "list_tags"),
]

READ_VERBS = ("Describe", "List", "Get", "BatchGet", "Generate", "Lookup", "Search", "Head")
POLICY_LIMIT = 6000  # IAM managed policies may hold 6144 characters (whitespace excluded)


def action_for(client: str, api: str) -> str:
    if client in ("apigateway", "apigatewayv2"):
        return "apigateway:GET"  # API Gateway authorizes by HTTP verb on resource ARNs
    if client in ("s3", "s3control"):
        name = S3_ACTIONS.get((client, api)) or botomodel.operation_name(client, api)
        return f"s3:{name}"
    return f"{CLIENT_PREFIX.get(client, client)}:{botomodel.operation_name(client, api)}"


def collect_actions(spec: CollectSpec, enabled_only: bool = True) -> list[str]:
    actions: set[str] = set()
    for svc in spec.services:
        if enabled_only and not svc.enabled:
            continue
        for a in svc.apis:
            actions.add(action_for(a.client or svc.client, a.api))
    actions.update(action_for(c, api) for c, api in HELPER_CALLS)
    bad = [x for x in actions if not x.split(":", 1)[1].startswith(READ_VERBS) and x != "apigateway:GET"]
    if bad:  # the spec validator already blocks mutating names; this is the second line of defence
        raise ValueError(f"non read-only actions in the policy: {sorted(bad)}")
    return sorted(actions)


def policy_documents(spec: CollectSpec, enabled_only: bool = True, limit: int = POLICY_LIMIT) -> list[dict]:
    """Split the actions over as many policy documents as the size limit needs."""
    docs: list[dict] = []
    current: list[str] = []

    def doc(actions: list[str], n: int) -> dict:
        return {"Version": "2012-10-17",
                "Statement": [{"Sid": f"CspmReadOnly{n}", "Effect": "Allow", "Action": actions, "Resource": "*"}]}

    for action in collect_actions(spec, enabled_only):
        if current and len(json.dumps(doc(current + [action], len(docs) + 1), separators=(",", ":"))) > limit:
            docs.append(doc(current, len(docs) + 1))
            current = []
        current.append(action)
    if current:
        docs.append(doc(current, len(docs) + 1))
    return docs
