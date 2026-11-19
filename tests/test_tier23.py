"""Tier 2/3 services on moto. moto does not implement every API: those calls must surface as status rows,
never as crashes, and no secret may reach the database."""
import json
import os
from pathlib import Path

import boto3
import mongomock
import pytest
from moto import mock_aws

from cspm_collector.collectors.base import CollectContext, get_collector
from cspm_collector.core.config import AccountSettings, MongoSettings, Settings
from cspm_collector.core.scan import ScanFilter, run_scan
from cspm_collector.core.session import AccountSession
from cspm_collector.spec.loader import load_spec, validate_spec
from cspm_collector.storage.store import Store

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
R = "us-east-1"
SECRET = "hunter2hunter2"
MASK = "***MASKED***"


def _setup(role: str, subnets: list[str]) -> None:
    c = lambda name: boto3.client(name, region_name=R)  # noqa: E731
    ecs = c("ecs")
    ecs.create_cluster(clusterName="cl1", tags=[{"key": "env", "value": "prod"}])
    ecs.register_task_definition(family="td1", containerDefinitions=[{
        "name": "a", "image": "x", "memory": 64,
        "environment": [{"name": "DB_PASSWORD", "value": SECRET}, {"name": "MODE", "value": "prod"}]}])
    ecs.create_service(cluster="cl1", serviceName="svc1", taskDefinition="td1", desiredCount=0)
    c("eks").create_cluster(name="eks1", roleArn=role, resourcesVpcConfig={"subnetIds": subnets})
    c("eks").create_nodegroup(clusterName="eks1", nodegroupName="ng1", subnets=subnets, nodeRole=role)
    c("dynamodb").create_table(TableName="t1", KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                               AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                               BillingMode="PAY_PER_REQUEST", Tags=[{"Key": "env", "Value": "prod"}])
    c("opensearch").create_domain(DomainName="dom1", TagList=[{"Key": "env", "Value": "prod"}])
    c("kinesis").create_stream(StreamName="ks1", ShardCount=1)
    c("stepfunctions").create_state_machine(
        name="sm1", roleArn=role, definition=json.dumps({"StartAt": "A", "States": {
            "A": {"Type": "Pass", "Result": f"password={SECRET}", "End": True}}}))
    c("cloudformation").create_stack(
        StackName="stk1", TemplateBody=json.dumps({"Parameters": {"DbPassword": {"Type": "String"}, "Env": {"Type": "String"}},
                                                    "Resources": {"Q": {"Type": "AWS::SQS::Queue"}}}),
        Parameters=[{"ParameterKey": "DbPassword", "ParameterValue": f"password={SECRET}"},
                    {"ParameterKey": "Env", "ParameterValue": "prod"}])
    glue = c("glue")
    glue.create_connection(ConnectionInput={"Name": "conn1", "ConnectionType": "JDBC", "ConnectionProperties": {
        "JDBC_CONNECTION_URL": "jdbc:x", "USERNAME": "u", "PASSWORD": SECRET}})
    glue.create_job(Name="job1", Role=role, Command={"Name": "glueetl", "ScriptLocation": "s3://b/s.py"},
                    DefaultArguments={"--password": SECRET, "--enable-metrics": "true"})
    sm = c("sagemaker")
    sm.create_notebook_instance(NotebookInstanceName="nb1", InstanceType="ml.t2.medium", RoleArn=role)
    sm.create_model(ModelName="m1", ExecutionRoleArn=role, PrimaryContainer={"Image": "x", "Environment": {"API_KEY": SECRET}})
    c("ecr").create_repository(repositoryName="repo1", tags=[{"Key": "env", "Value": "prod"}])
    c("athena").create_work_group(Name="wg1")
    c("batch").register_job_definition(jobDefinitionName="jd1", type="container", containerProperties={
        "image": "x", "vcpus": 1, "memory": 64, "environment": [{"name": "TOKEN", "value": SECRET}]})
    c("backup").create_backup_vault(BackupVaultName="bv1")
    c("mq").create_broker(BrokerName="b1", EngineType="ActiveMQ", EngineVersion="5.15.0", HostInstanceType="mq.t2.micro",
                          DeploymentMode="SINGLE_INSTANCE", Users=[{"Username": "u", "Password": "Passw0rd-Xyz123"}],
                          AutoMinorVersionUpgrade=False, PubliclyAccessible=False)
    c("ssm").create_document(Name="doc1", DocumentType="Command", DocumentFormat="JSON", Content=json.dumps({
        "schemaVersion": "2.2", "description": f"password={SECRET}",
        "mainSteps": [{"action": "aws:runShellScript", "name": "s", "inputs": {"runCommand": ["echo hi"]}}]}))
    c("dms").create_replication_instance(ReplicationInstanceIdentifier="ri1", ReplicationInstanceClass="dms.t2.micro")
    c("firehose").create_delivery_stream(DeliveryStreamName="fh1", ExtendedS3DestinationConfiguration={
        "RoleARN": role, "BucketARN": "arn:aws:s3:::b"})
    c("appsync").create_graphql_api(name="gql1", authenticationType="API_KEY")
    c("neptune").create_db_cluster(DBClusterIdentifier="nn1", Engine="neptune")
    c("elasticache").create_cache_cluster(CacheClusterId="cc1", Engine="redis", CacheNodeType="cache.t3.micro", NumCacheNodes=1)
    c("redshift").create_cluster(ClusterIdentifier="rs1", NodeType="dc2.large", MasterUsername="a", MasterUserPassword="Passw0rd-Xyz123")
    c("transfer").create_server()


@pytest.fixture(scope="module")
def world():
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_DEFAULT_REGION": R}.items():
        os.environ.setdefault(k, v)
    with mock_aws():
        role = boto3.client("iam", region_name=R).create_role(
            RoleName="r", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}))["Role"]["Arn"]
        ec2 = boto3.client("ec2", region_name=R)
        _setup(role, [s["SubnetId"] for s in ec2.describe_subnets()["Subnets"][:2]])
        settings = Settings(accounts=[AccountSettings(account_id="123456789012", regions=[R])])
        spec = load_spec(SPEC)
        store = Store(mongomock.MongoClient()["cspm"], MongoSettings())
        names = {s.service for s in spec.services if s.enabled and s.tier in (2, 3)}
        summary = run_scan(settings, spec, store, flt=ScanFilter(services=names))
        yield {"store": store, "sid": summary.scan_id, "summary": summary, "spec": spec, "names": names}


def one(world, service, rtype, rid=None):
    q = {"service": service, "resource_type": rtype, **({"resource_id": rid} if rid else {})}
    return world["store"].db.resources.find_one(q)


def row(world, service, api):
    return world["store"].db.collection_status.find_one({"scan_id": world["sid"], "service": service, "api": api})


# ----------------------------------------------------------------------------- the spec itself
def test_every_service_but_the_tag_dump_is_curated_and_enabled():
    spec = load_spec(SPEC)
    disabled = [s.service for s in spec.services if not s.enabled]
    assert disabled == ["resourcegroupstaggingapi"]  # heavy by design: opt-in
    assert [i for i in validate_spec(spec) if i.level == "error"] == []
    assert not any(a.needs_review for s in spec.services for a in s.apis if s.enabled)


def test_every_collector_named_in_the_spec_exists():
    for s in load_spec(SPEC).services:
        get_collector(s.collector)


def test_global_service_api_region_override():
    spec = {s.service: s for s in load_spec(SPEC).services}
    ctx = CollectContext(account=AccountSession.__new__(AccountSession), region="global", service=spec["globalaccelerator"])
    assert ctx.aws_region == "us-west-2"
    assert CollectContext(account=None, region="global", service=spec["iam"]).aws_region == "us-east-1"
    assert CollectContext(account=None, region="eu-west-1", service=spec["ecs"]).aws_region == "eu-west-1"


def test_scan_survives_apis_moto_does_not_implement(world):
    s = world["store"]
    seen = set(s.db.collection_status.distinct("service", {"scan_id": world["sid"]}))
    assert world["names"] <= seen  # every Tier 2/3 service left status rows
    assert world["summary"].status == "PARTIAL"
    assert s.db.collection_status.count_documents({"scan_id": world["sid"], "status": "ERROR"}) > 10


def test_no_secret_reaches_any_collection(world):
    s = world["store"]
    blob = json.dumps([d for c in s.db.list_collection_names() for d in s.db[c].find({})], default=str)
    assert SECRET not in blob


# ----------------------------------------------------------------------------- masking in context
def test_ecs_services_task_definition_env_masked(world):
    cluster = one(world, "ecs", "cluster")
    assert cluster["resource_id"].endswith(":cluster/cl1") and cluster["tags"] == [{"key": "env", "value": "prod"}]
    svc = one(world, "ecs", "service")
    assert svc["resource_id"].endswith("/svc1") and svc["parent"] == {"resource_type": "cluster", "resource_id": cluster["resource_id"]}
    assert svc["cluster_arn"] == cluster["resource_id"]
    assert row(world, "ecs", "describe_services")["resource_count"] == 1 and row(world, "ecs", "describe_services")["status"] == "SUCCESS"

    td = one(world, "ecs", "task_definition")
    env = td["config"]["_details"]["describe_task_definition"]["taskDefinition"]["containerDefinitions"][0]["environment"]
    assert env == [{"name": "DB_PASSWORD", "value": MASK}, {"name": "MODE", "value": MASK}]  # names kept, values gone
    assert [f["type"] for f in td["secret_findings"]] == ["password_assignment"]


def test_secret_bearing_settings_are_masked(world):
    conn = one(world, "glue", "connection", "conn1")["config"]["ConnectionProperties"]
    # HidePassword=true already drops PASSWORD (moto honours it, AWS does too); everything left is masked anyway
    assert {"JDBC_CONNECTION_URL", "USERNAME"} <= set(conn) and set(conn.values()) == {MASK}
    args = one(world, "glue", "job", "job1")["config"]["DefaultArguments"]
    assert args == {"--password": MASK, "--enable-metrics": "true"}  # selective: harmless settings stay readable

    sm = one(world, "sagemaker", "model", "m1")["config"]["_details"]["describe_model"]["PrimaryContainer"]["Environment"]
    assert sm == {"API_KEY": MASK}
    jd = one(world, "batch", "job_definition")["config"]["containerProperties"]["environment"]
    assert jd == [{"name": "TOKEN", "value": MASK}]

    stack = one(world, "cloudformation", "stack", None)["config"]["Parameters"]
    assert {p["ParameterKey"]: p["ParameterValue"] for p in stack} == {"DbPassword": MASK, "Env": "prod"}

    sf = one(world, "stepfunctions", "state_machine")
    assert sf["config"]["_details"]["describe_state_machine"]["definition"] == MASK
    assert [f["type"] for f in sf["secret_findings"]] == ["password_assignment"]
    doc = one(world, "ssm", "document", "doc1")
    assert doc["config"]["_details"]["get_document"]["Content"] == MASK and doc["secret_findings"]


# ----------------------------------------------------------------------------- collectors with fan-out / built ARNs
def test_eks_nodegroup_documents_and_cluster_arn(world):
    cluster = one(world, "eks", "cluster", "eks1")
    assert cluster["arn"].endswith(":cluster/eks1") and "describe_cluster" in cluster["config"]["_details"]
    ng = one(world, "eks", "nodegroup", "eks1|ng1")
    assert ng["parent"] == {"resource_type": "cluster", "resource_id": "eks1"} and ng["arn"].startswith("arn:aws:eks:")


def test_dynamodb_built_arn_tags_and_details(world):
    t = one(world, "dynamodb", "table", "t1")
    assert t["arn"] == "arn:aws:dynamodb:us-east-1:123456789012:table/t1"
    assert t["tags"] == [{"key": "env", "value": "prod"}]
    assert {"describe_table", "describe_continuous_backups"} <= set(t["config"]["_details"])


def test_opensearch_arn_from_detail_and_tags(world):
    d = one(world, "opensearch", "domain", "dom1")
    assert d["arn"].endswith(":domain/dom1") and d["tags"] == [{"key": "env", "value": "prod"}]
    assert "describe_domain_config" in d["config"]["_details"]


def test_arn_from_and_scalar_ids(world):
    ks = one(world, "kinesis", "stream", "ks1")
    assert ks["arn"].endswith(":stream/ks1") and "describe_stream_summary" in ks["config"]["_details"]
    fh = one(world, "firehose", "delivery_stream", "fh1")
    assert fh["arn"].endswith(":deliverystream/fh1")


def test_plain_services_collect(world):
    for service, rtype in [("appsync", "graphql_api"), ("athena", "work_group"), ("backup", "backup_vault"),
                           ("dms", "replication_instance"), ("ecr", "repository"), ("elasticache", "cache_cluster"),
                           ("redshift", "cluster"), ("transfer", "server"), ("sagemaker", "notebook_instance"),
                           ("mq", "broker")]:
        assert one(world, service, rtype), (service, rtype)
    assert one(world, "ecr", "repository")["tags"] == [{"key": "env", "value": "prod"}]


def test_engine_filter_keeps_other_engines_out(world):
    nn = one(world, "neptune", "db_cluster", "nn1")
    assert nn and row(world, "neptune", "describe_db_clusters")["status"] == "SUCCESS"


def test_opt_in_calls_are_skipped_not_failed(world):
    for service, api in [("sagemaker", "list_training_jobs"), ("sagemaker", "describe_training_job"),
                         ("ecr", "describe_images")]:
        r = row(world, service, api)
        assert r["status"] == "SKIPPED" and "opt-in flag" in r["error"], (service, api)
