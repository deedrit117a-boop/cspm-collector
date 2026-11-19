"""--retry-failed, one failing account/collector never stops the rest, helper-call failures."""
from pathlib import Path
from unittest import mock

import boto3
import mongomock
import pytest
from moto import mock_aws

from cspm_collector.collectors.base import CollectOptions
from cspm_collector.core.call import CallResult
from cspm_collector.core.config import AccountSettings, AkamaiAccountSettings, MongoSettings, Settings
from cspm_collector.core.errors import Status
from cspm_collector.core.scan import RetryPlan, ScanFilter, plan_retry, run_scan
from cspm_collector.core.session import AccountSession
from cspm_collector.core.workers import Task
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
R = "us-east-1"
ACCT = "123456789012"


@pytest.fixture
def env():
    with mock_aws():
        settings = Settings(accounts=[AccountSettings(account_id=ACCT, regions=[R])])
        yield settings, load_spec(SPEC), Store(mongomock.MongoClient()["cspm"], MongoSettings())


def scan(env, services, **kw):
    settings, spec, store = env
    return run_scan(settings, spec, store, flt=kw.pop("flt", None) or ScanFilter(services=set(services.split(","))), **kw)


def answer(service_name, api, result):
    """Replace one API's answer with a canned CallResult (everything else goes to moto)."""
    from cspm_collector.collectors import generic

    real = generic.call_api

    def patched(client, service, name, *a, **kw):
        if service == service_name and name == api:
            return result
        return real(client, service, name, *a, **kw)

    return mock.patch.object(generic, "call_api", patched)


def deny(service_name, api):
    return answer(service_name, api, CallResult(Status.ACCESS_DENIED, error_code="AccessDenied"))


# ------------------------------------------------------------------------------------------ retry
def test_retry_redoes_only_what_failed(env):
    boto3.client("sns", region_name=R).create_topic(Name="t1")
    boto3.client("sqs", region_name=R).create_queue(QueueName="q1")
    with deny("sns", "list_topics"):
        first = scan(env, "sns,sqs")
    assert first.status == "PARTIAL" and first.tasks == 2

    store = env[2]
    plan = plan_retry(store, first.scan_id)
    assert plan.tasks == frozenset({(ACCT, R, "sns")}) and not plan.accounts and not plan.akamai

    second = scan(env, "sns,sqs", flt=ScanFilter(services={"sns", "sqs"}, retry=plan))
    assert second.tasks == 1 and second.status == "COMPLETED"  # sqs was not collected again
    assert store.db.scans.find_one({"scan_id": second.scan_id})["options"]["retry_of"] == first.scan_id
    assert store.db.resources.find_one({"service": "sns", "resource_type": "topic"})["scan_id"] == second.scan_id
    assert store.db.resources.find_one({"service": "sqs", "resource_type": "queue"})["scan_id"] == first.scan_id
    assert store.db.collection_status.count_documents({"scan_id": second.scan_id, "service": "sqs"}) == 0


def test_retry_with_nothing_failed_is_a_clean_noop(env):
    boto3.client("sqs", region_name=R).create_queue(QueueName="q1")
    first = scan(env, "sqs")
    plan = plan_retry(env[2], first.scan_id)
    again = scan(env, "sqs", flt=ScanFilter(services={"sqs"}, retry=plan))
    assert (again.tasks, again.status) == (0, "COMPLETED")


def test_plan_retry_reads_account_collector_and_akamai_failures():
    store = Store(mongomock.MongoClient()["cspm"], MongoSettings())
    store.create_scan("s1", [], "v")
    from cspm_collector.storage.records import StatusRecord

    store.record_status("s1", [
        StatusRecord(ACCT, "*", "*", "*", Status.ERROR),  # account setup failed
        StatusRecord("999", "eu-west-1", "ec2", "*", Status.ERROR),  # collector crashed
        StatusRecord("999", "global", "iam", "list_users", Status.THROTTLED_GIVEUP),
        StatusRecord("999", "us-east-1", "s3", "list_buckets", Status.SUCCESS),
        StatusRecord("999", "us-east-1", "kms", "describe_key", Status.NOT_ENABLED),  # a valid outcome, not a failure
        StatusRecord("akamai:main", "global", "akamai", "papi_rules", Status.ERROR),
    ])
    plan = plan_retry(store, "s1")
    assert plan.accounts == {ACCT} and plan.akamai == {"main"}
    assert plan.tasks == {("999", "eu-west-1", "ec2"), ("999", "global", "iam")}
    assert plan.wants(Task(ACCT, "anywhere", "anything")) and plan.wants(Task("999", "global", "iam"))
    assert not plan.wants(Task("999", "us-east-1", "s3")) and plan.wants_account("999")

    with pytest.raises(ValueError, match="unknown scan"):
        plan_retry(store, "missing")


def test_akamai_account_is_retried_as_one_unit(env):
    settings, spec, store = env
    settings.akamai = [AkamaiAccountSettings(name="main"), AkamaiAccountSettings(name="other")]
    assert not ScanFilter(retry=RetryPlan("s", akamai=frozenset({"main"}))).wants_akamai(settings.akamai[1])
    assert ScanFilter(retry=RetryPlan("s", akamai=frozenset({"main"}))).wants_akamai(settings.akamai[0])
    assert not ScanFilter(retry=RetryPlan("s")).wants_akamai(settings.akamai[0])


# ------------------------------------------------------------------------------------------ isolation
def test_a_failing_account_does_not_stop_the_others(env):
    settings, spec, store = env
    settings.accounts = [AccountSettings(account_id="111111111111", regions=[R]),
                         AccountSettings(account_id=ACCT, regions=[R])]
    boto3.client("sqs", region_name=R).create_queue(QueueName="q1")

    def factory(acct):
        if acct.account_id == "111111111111":
            raise RuntimeError("cannot assume role")
        return AccountSession(acct)

    s = run_scan(settings, spec, store, flt=ScanFilter(services={"sqs"}), session_factory=factory)
    assert s.status == "PARTIAL"
    bad = store.db.collection_status.find_one({"scan_id": s.scan_id, "account_id": "111111111111"})
    assert bad["status"] == "ERROR" and bad["region"] == "*" and "cannot assume role" in bad["error"]
    assert store.db.resources.count_documents({"service": "sqs", "account_id": ACCT}) == 1

    plan = plan_retry(store, s.scan_id)
    assert plan.accounts == {"111111111111"}  # the whole account is retried, not one service


def test_a_bug_in_one_resource_is_one_internal_row_and_the_rest_is_kept(env):
    from cspm_collector.collectors.sqs import SqsCollector

    boto3.client("sqs", region_name=R).create_queue(QueueName="q1")
    with mock.patch.object(SqsCollector, "enrich", side_effect=RuntimeError("boom")):
        s = scan(env, "sqs")
    store = env[2]
    row = store.db.collection_status.find_one({"scan_id": s.scan_id, "api": "_internal"})
    assert row["status"] == "ERROR" and row["error_code"] == "RuntimeError" and row["affects_sweep"] is False
    assert store.db.resources.count_documents({"service": "sqs", "resource_type": "queue"}) == 1


def test_helper_call_failure_blocks_the_sweep_of_its_resource_type(env):
    """ECS services come from helper calls (list_services/describe_services): when those fail, services that were
    collected earlier must not be soft-deleted."""
    ecs = boto3.client("ecs", region_name=R)
    ecs.create_cluster(clusterName="cl1")
    ecs.register_task_definition(family="td1", containerDefinitions=[{"name": "a", "image": "x", "memory": 64}])
    ecs.create_service(cluster="cl1", serviceName="svc1", taskDefinition="td1", desiredCount=0)
    scan(env, "ecs")
    store = env[2]
    assert store.db.resources.count_documents({"service": "ecs", "resource_type": "service"}) == 1

    with deny("ecs", "list_services"):
        failed = scan(env, "ecs")
    assert failed.status == "PARTIAL"
    svc = store.db.resources.find_one({"service": "ecs", "resource_type": "service"})
    assert svc.get("deleted_at") is None  # listing failed: absence would prove nothing
    cluster = store.db.resources.find_one({"service": "ecs", "resource_type": "cluster"})
    assert cluster["config"]["_errors"]["list_services"] == "AccessDenied"

    # listing works again and reports no services (moto keeps deleted ECS services listed, so say it explicitly)
    with answer("ecs", "list_services", CallResult(Status.SUCCESS, pages=[{"serviceArns": []}])):
        scan(env, "ecs")
    assert store.db.resources.find_one({"service": "ecs", "resource_type": "service"})["deleted_at"] is not None


def test_opt_in_flags_reach_the_collectors(env):
    s = scan(env, "ecr", options=CollectOptions(flags=frozenset({"--collect-ecr-images"})))
    row = env[2].db.collection_status.find_one({"scan_id": s.scan_id, "api": "describe_images"})
    assert row["status"] == "SUCCESS"  # no repositories: nothing to call, but it is no longer SKIPPED


# ------------------------------------------------------------------------------------------ region availability
def test_region_supported_uses_botocore_endpoint_data_and_never_guesses():
    from cspm_collector.core.session import region_supported

    assert region_supported("ec2", "ap-northeast-2")
    assert not region_supported("apprunner", "ap-northeast-2")  # App Runner does not exist in Seoul
    assert not region_supported("datapipeline", "ap-northeast-2")
    assert region_supported("a-service-newer-than-this-botocore", "ap-northeast-2")  # no data: never skip


def test_unavailable_services_are_skipped_without_a_single_call(env):
    settings, spec, store = env
    settings.accounts = [AccountSettings(account_id=ACCT, regions=["ap-northeast-2"])]
    boto3.client("sqs", region_name="ap-northeast-2").create_queue(QueueName="q1")
    s = run_scan(settings, spec, store, flt=ScanFilter(services={"sqs", "apprunner", "datapipeline"}))
    assert s.tasks == 1 and s.status == "COMPLETED"  # only sqs ran; the others never touched the network
    rows = {r["service"]: r for r in store.db.collection_status.find({"scan_id": s.scan_id, "api": "*"})}
    assert set(rows) == {"apprunner", "datapipeline"}
    assert rows["apprunner"]["status"] == "NOT_SUPPORTED" and "not available in this region" in rows["apprunner"]["error"]
    assert rows["apprunner"]["affects_sweep"] is False
    assert plan_retry(store, s.scan_id).tasks == frozenset()  # not a failure: nothing to retry


def test_the_skip_can_be_turned_off(env):
    settings, spec, store = env
    settings.accounts = [AccountSettings(account_id=ACCT, regions=["ap-northeast-2"])]
    settings.skip_unsupported_regions = False
    s = run_scan(settings, spec, store, flt=ScanFilter(services={"apprunner"}))
    assert s.tasks == 1  # the service is called after all (and fails or not, depending on the account)
