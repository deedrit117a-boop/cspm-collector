"""ECS running tasks: stored per task, environment overrides masked, a failing helper call never sweeps stored tasks away."""
import boto3

from cspm_collector.core.call import CallResult
from cspm_collector.core.errors import Status

from test_retry_and_robustness import ACCT, R, answer, deny, env, scan  # noqa: F401

SECRET = "hunter2hunter2"
ARN = f"arn:aws:ecs:{R}:{ACCT}:task/cl1/aaaa1111"


def _cluster():
    boto3.client("ecs", region_name=R).create_cluster(clusterName="cl1")


def _tasks(*arns):
    return answer("ecs", "list_tasks", CallResult(Status.SUCCESS, pages=[{"taskArns": list(arns)}]))


def _described(task):
    return answer("ecs", "describe_tasks", CallResult(Status.SUCCESS, pages=[{"tasks": [task]}]))


def _task(arn=ARN):
    return {"taskArn": arn, "lastStatus": "RUNNING", "taskDefinitionArn": f"arn:aws:ecs:{R}:{ACCT}:task-definition/td1:1",
            "group": "service:svc1", "tags": [{"key": "env", "value": "prod"}],
            "overrides": {"containerOverrides": [{"name": "a", "environment": [
                {"name": "DB_PASSWORD", "value": SECRET}, {"name": "MODE", "value": "prod"}]}]}}


def test_tasks_are_stored_with_masked_overrides(env):
    _cluster()
    with _tasks(ARN), _described(_task()):
        res = scan(env, "ecs")
    store = env[2]
    doc = store.db.resources.find_one({"service": "ecs", "resource_type": "task"})
    assert doc["resource_id"] == ARN and doc["parent"]["resource_type"] == "cluster"
    assert doc["config"]["lastStatus"] == "RUNNING"
    env_vars = {e["name"]: e["value"] for e in doc["config"]["overrides"]["containerOverrides"][0]["environment"]}
    assert env_vars == {"DB_PASSWORD": "***MASKED***", "MODE": "***MASKED***"}
    assert SECRET not in str(list(store.db.resources.find({})))
    assert res.status in ("COMPLETED", "PARTIAL")


def test_failed_task_listing_keeps_stored_tasks(env):
    _cluster()
    with _tasks(ARN), _described(_task()):
        scan(env, "ecs")
    store = env[2]
    with deny("ecs", "list_tasks"):
        scan(env, "ecs")
    assert store.db.resources.find_one({"service": "ecs", "resource_type": "task"}).get("deleted_at") is None
    assert store.db.resources.find_one({"service": "ecs", "resource_type": "cluster"})["config"]["_errors"]["list_tasks"] == "AccessDenied"


def test_tasks_that_are_gone_get_soft_deleted(env):
    _cluster()
    with _tasks(ARN), _described(_task()):
        scan(env, "ecs")
    with _tasks():
        scan(env, "ecs")
    assert env[2].db.resources.find_one({"service": "ecs", "resource_type": "task"})["deleted_at"] is not None


def test_more_than_100_tasks_are_described_in_batches(env):
    _cluster()
    arns = [f"arn:aws:ecs:{R}:{ACCT}:task/cl1/t{i:04d}" for i in range(230)]
    seen = []

    def described(arns_in):
        return CallResult(Status.SUCCESS, pages=[{"tasks": [_task(a) for a in arns_in]}])

    from unittest import mock
    from cspm_collector.collectors import generic
    real = generic.call_api

    def patched(client, service, name, params=None, *a, **kw):
        if service == "ecs" and name == "list_tasks":
            return CallResult(Status.SUCCESS, pages=[{"taskArns": arns}])
        if service == "ecs" and name == "describe_tasks":
            seen.append(len(params["tasks"]))
            return described(params["tasks"])
        return real(client, service, name, params, *a, **kw)

    with mock.patch.object(generic, "call_api", patched):
        scan(env, "ecs")
    assert seen == [100, 100, 30]
    assert env[2].db.resources.count_documents({"service": "ecs", "resource_type": "task"}) == 230


# ------------------------------------------------------------------ container instances and the joins
CI_ARN = f"arn:aws:ecs:{R}:{ACCT}:container-instance/cl1/ci1"


def _with(*makers):
    """Enter the patches one after the other: each ``answer`` wraps whatever call_api is at that moment."""
    from contextlib import ExitStack
    stack = ExitStack()
    for make in makers:
        stack.enter_context(make())
    return stack


def _ec2_task():
    t = _task()
    t.update(launchType="EC2", containerInstanceArn=CI_ARN, clusterArn=f"arn:aws:ecs:{R}:{ACCT}:cluster/cl1",
             containers=[{"name": "a", "networkBindings": [{"containerPort": 80, "hostPort": 32768, "protocol": "tcp"}],
                          "networkInterfaces": [{"privateIpv4Address": "10.0.1.5"}]}])
    return t


def _ci_calls():
    return (lambda: answer("ecs", "list_container_instances", CallResult(Status.SUCCESS, pages=[{"containerInstanceArns": [CI_ARN]}])),
            lambda: answer("ecs", "describe_container_instances", CallResult(Status.SUCCESS, pages=[{"containerInstances": [
                {"containerInstanceArn": CI_ARN, "ec2InstanceId": "i-0abc", "status": "ACTIVE", "runningTasksCount": 1}]}])))


def test_container_instances_are_stored_and_joined_to_tasks(env):
    _cluster()
    with _with(*_ci_calls(), lambda: _tasks(ARN), lambda: _described(_ec2_task())):
        scan(env, "ecs")
    store = env[2]
    ci = store.db.resources.find_one({"service": "ecs", "resource_type": "container_instance"})
    assert ci["resource_id"] == CI_ARN and ci["ec2_instance_id"] == "i-0abc" and ci["config"]["status"] == "ACTIVE"
    t = store.db.resources.find_one({"service": "ecs", "resource_type": "task"})
    assert t["ec2_instance_id"] == "i-0abc" and t["container_instance_arn"] == CI_ARN
    assert t["service_name"] == "svc1" and t["private_ips"] == ["10.0.1.5"] and t["launch_type"] == "EC2"
    assert t["config"]["containers"][0]["networkBindings"][0]["hostPort"] == 32768


def test_fargate_task_has_no_instance_but_keeps_its_ips(env):
    _cluster()
    task = _task()
    task.update(launchType="FARGATE", containers=[{"name": "a", "networkInterfaces": [{"privateIpv4Address": "10.0.2.9"}]}])
    with _tasks(ARN), _described(task):
        scan(env, "ecs")
    t = env[2].db.resources.find_one({"service": "ecs", "resource_type": "task"})
    assert t["ec2_instance_id"] is None and t["private_ips"] == ["10.0.2.9"] and t["launch_type"] == "FARGATE"


def test_failed_instance_listing_is_recorded_and_keeps_stored_instances(env):
    _cluster()
    with _with(*_ci_calls()):
        scan(env, "ecs")
    store = env[2]
    with deny("ecs", "list_container_instances"):
        scan(env, "ecs")
    assert store.db.resources.find_one({"service": "ecs", "resource_type": "container_instance"}).get("deleted_at") is None
    assert store.db.resources.find_one({"service": "ecs", "resource_type": "cluster"})["config"]["_errors"]["list_container_instances"] == "AccessDenied"


def test_task_edges_to_service_instance_and_ip():
    from cspm_collector.core.edges import extract_edges
    from cspm_collector.storage.records import ResourceRecord
    from cspm_collector.collectors.misc import EcsCollector

    task = _ec2_task()
    rec = ResourceRecord(account_id=ACCT, region=R, service="ecs", resource_type="task", resource_id=ARN, config=task, arn=ARN,
                         extra={"cluster_arn": task["clusterArn"], **EcsCollector._task_facts(task, {CI_ARN: "i-0abc"})})
    edges = {(e["rel"], e["dst_type"], e["dst_id"]): e for e in extract_edges([rec])}
    assert ("belongs_to_service", "service", f"arn:aws:ecs:{R}:{ACCT}:service/cl1/svc1") in edges
    inst = edges[("runs_on_instance", "instance", "i-0abc")]
    assert inst["dst_key"]  # a stored EC2 instance document has this key
    assert ("has_private_ip", "ip", "10.0.1.5") in edges and ("in_cluster", "cluster", task["clusterArn"]) in edges
