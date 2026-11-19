"""Small collectors for services whose detail calls need two parents (cluster + service name) or a
constructed ARN. Everything else about them is in the spec."""
from __future__ import annotations

from cspm_collector.spec.schema import ApiSpec
from cspm_collector.storage.records import ResourceRecord

from .base import register
from .generic import Entry, GenericCollector
from .masking import apply_mask


class _FanOut(GenericCollector):
    """Helpers for 'list children of each parent, then describe them' services."""

    def _child_resources(self, rtype: str, parent: Entry, parent_type: str, items: list[tuple[str, dict, str | None]],
                         extra: dict | None = None, per_item: dict[str, dict] | None = None) -> None:
        with self._lock:
            for rid, config, arn in items:
                self.result.resources.append(ResourceRecord(
                    account_id=self.ctx.account_id, region=self.ctx.region, service=self.ctx.service.service,
                    resource_type=rtype, resource_id=rid, config=config, arn=arn,
                    tags=config.get("tags") or config.get("Tags"),
                    extra={**(extra or {}), **((per_item or {}).get(rid) or {}),
                           "parent": {"resource_type": parent_type, "resource_id": parent.rid}}))

    def _declare(self, name: str, rtype: str) -> None:
        self._extra_meta[name] = (rtype, True)  # a failed call must block the soft-delete sweep of that type


@register("ecs")
class EcsCollector(_FanOut):
    """Services are described per cluster in batches of 10 (the API limit) and stored as their own documents."""

    def after_roots(self) -> None:
        self._declare("list_services", "service")
        self._declare("describe_services", "service")
        self._declare("list_tasks", "task")
        self._declare("describe_tasks", "task")
        self._declare("list_container_instances", "container_instance")
        self._declare("describe_container_instances", "container_instance")

    def enrich(self, root: ApiSpec, entry: Entry) -> None:
        if root.api != "list_clusters":
            return
        instances = self._container_instances(entry)  # first: tasks take the EC2 instance id from it
        self._tasks(entry, instances)
        listed = self.call("list_services", {"cluster": entry.rid}, self.ctx.client(), paginate=True)
        if not listed.ok:
            entry.errors["list_services"] = listed.error_code
            return
        arns = [a for page in listed.pages for a in page.get("serviceArns", [])]
        for i in range(0, len(arns), 10):
            res = self.call("describe_services", {"cluster": entry.rid, "services": arns[i:i + 10], "include": ["TAGS"]},
                            self.ctx.client(), paginate=False)
            if not res.ok:
                entry.errors["describe_services"] = res.error_code
                continue
            services = res.pages[0].get("services", [])
            self._child_resources("service", entry, "cluster",
                                  [(s["serviceArn"], s, s["serviceArn"]) for s in services],
                                  {"cluster_arn": entry.rid})
            with self._lock:
                self._aggs["describe_services"].count += len(services)

    def _container_instances(self, entry: Entry) -> dict[str, str]:
        """EC2 container instances of the cluster (none for Fargate-only clusters). Stored as their own documents, with
        ``ec2_instance_id`` on top level: it joins a task (``containerInstanceArn``) to the EC2 server. Returns
        ``{containerInstanceArn: ec2InstanceId}``."""
        listed = self.call("list_container_instances", {"cluster": entry.rid}, self.ctx.client(), paginate=True)
        if not listed.ok:
            entry.errors["list_container_instances"] = listed.error_code
            return {}
        arns = [a for page in listed.pages for a in page.get("containerInstanceArns", [])]
        joined: dict[str, str] = {}
        for i in range(0, len(arns), 100):
            res = self.call("describe_container_instances", {"cluster": entry.rid, "containerInstances": arns[i:i + 100],
                                                             "include": ["TAGS"]}, self.ctx.client(), paginate=False)
            if not res.ok:
                entry.errors["describe_container_instances"] = res.error_code
                continue
            found = res.pages[0].get("containerInstances", [])
            joined.update({c["containerInstanceArn"]: c["ec2InstanceId"] for c in found if c.get("ec2InstanceId")})
            self._child_resources("container_instance", entry, "cluster",
                                  [(c["containerInstanceArn"], c, c["containerInstanceArn"]) for c in found],
                                  {"cluster_arn": entry.rid},
                                  {c["containerInstanceArn"]: {"ec2_instance_id": c.get("ec2InstanceId")} for c in found})
            with self._lock:
                self._aggs["describe_container_instances"].count += len(found)
        return joined

    @staticmethod
    def _task_facts(task: dict, instances: dict[str, str]) -> dict:
        """What a reader joins on, lifted out of the task configuration: the service, the EC2 server, the private IPs."""
        group = task.get("group") or ""
        arn = task.get("containerInstanceArn")
        ips = sorted({n["privateIpv4Address"] for c in task.get("containers") or [] if isinstance(c, dict)
                      for n in c.get("networkInterfaces") or [] if isinstance(n, dict) and n.get("privateIpv4Address")})
        return {"service_name": group[len("service:"):] if group.startswith("service:") else None,
                "container_instance_arn": arn, "ec2_instance_id": instances.get(arn) if arn else None, "private_ips": ips,
                "launch_type": task.get("launchType")}

    def _tasks(self, entry: Entry, instances: dict[str, str]) -> None:
        """Running tasks of the cluster (``list_tasks`` returns RUNNING ones by default; stopped tasks live for about an hour
        only and are left out). Described in batches of 100 (the API limit); the values of environment overrides are masked."""
        listed = self.call("list_tasks", {"cluster": entry.rid}, self.ctx.client(), paginate=True)
        if not listed.ok:
            entry.errors["list_tasks"] = listed.error_code
            return
        arns = [a for page in listed.pages for a in page.get("taskArns", [])]
        for i in range(0, len(arns), 100):
            res = self.call("describe_tasks", {"cluster": entry.rid, "tasks": arns[i:i + 100], "include": ["TAGS"]},
                            self.ctx.client(), paginate=False)
            if not res.ok:
                entry.errors["describe_tasks"] = res.error_code
                continue
            tasks = res.pages[0].get("tasks", [])
            for t in tasks:
                entry.findings += apply_mask(t, "pairs:overrides.containerOverrides[].environment|name|value",
                                             f"ecs.{entry.rid}.task.{t.get('taskArn', '?')}")
            self._child_resources("task", entry, "cluster", [(t["taskArn"], t, t["taskArn"]) for t in tasks],
                                  {"cluster_arn": entry.rid}, {t["taskArn"]: self._task_facts(t, instances) for t in tasks})
            with self._lock:
                self._aggs["describe_tasks"].count += len(tasks)


@register("eks")
class EksCollector(_FanOut):
    """Node groups need (cluster, nodegroup) together, so they are described here and stored separately."""

    def after_roots(self) -> None:
        self._declare("list_nodegroups", "nodegroup")
        self._declare("describe_nodegroup", "nodegroup")

    def enrich(self, root: ApiSpec, entry: Entry) -> None:
        if root.api != "list_clusters":
            return
        listed = self.call("list_nodegroups", {"clusterName": entry.rid}, self.ctx.client(), paginate=True)
        if not listed.ok:
            entry.errors["list_nodegroups"] = listed.error_code
            return
        for name in [n for page in listed.pages for n in page.get("nodegroups", [])]:
            res = self.call("describe_nodegroup", {"clusterName": entry.rid, "nodegroupName": name},
                            self.ctx.client(), paginate=False)
            if not res.ok:
                entry.errors[f"describe_nodegroup:{name}"] = res.error_code
                continue
            group = res.pages[0].get("nodegroup") or {}
            self._child_resources("nodegroup", entry, "cluster", [(f"{entry.rid}|{name}", group, group.get("nodegroupArn"))],
                                  {"cluster_name": entry.rid})
            with self._lock:
                self._aggs["describe_nodegroup"].count += 1


@register("dynamodb")
class DynamoDbCollector(GenericCollector):
    """DescribeTable has the ARN only inside the response, while tags and the resource policy need it as input."""

    def _arn(self, entry: Entry) -> str:
        return f"arn:aws:dynamodb:{self.ctx.region}:{self.ctx.account_id}:table/{entry.rid}"

    def arn_for(self, root: ApiSpec, entry: Entry):
        return self._arn(entry) if root.api == "list_tables" else super().arn_for(root, entry)

    def enrich(self, root: ApiSpec, entry: Entry) -> None:
        if root.api != "list_tables":
            return
        arn = self._arn(entry)
        for api in ("list_tags_of_resource", "get_resource_policy"):
            res = self.call(api, {"ResourceArn": arn}, self.ctx.client(), paginate=api == "list_tags_of_resource")
            if res.ok:
                entry.details[api] = None if res.empty else self._merge(res.pages)
            else:
                entry.errors[api] = res.error_code

    @staticmethod
    def _merge(pages: list[dict]) -> dict:
        from .paths import merge_pages

        return merge_pages(pages)

    def tags_for(self, root: ApiSpec, entry: Entry):
        return (entry.details.get("list_tags_of_resource") or {}).get("Tags")


@register("opensearch")
class OpenSearchCollector(GenericCollector):
    """ListTags needs the domain ARN, which only DescribeDomain returns."""

    def enrich(self, root: ApiSpec, entry: Entry) -> None:
        arn = self.arn_for(root, entry)
        if root.api != "list_domain_names" or not arn:
            return
        res = self.call("list_tags", {"ARN": arn}, self.ctx.client(), paginate=False)
        if res.ok and res.pages:
            entry.details["list_tags"] = res.pages[0]
        elif not res.ok:
            entry.errors["list_tags"] = res.error_code

    def tags_for(self, root: ApiSpec, entry: Entry):
        return (entry.details.get("list_tags") or {}).get("TagList")
