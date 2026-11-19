"""IAM: spec-driven lists/details plus inline policy documents, key usage and the credential report."""
from __future__ import annotations

import csv
import io
import time

from cspm_collector.core.errors import Status
from cspm_collector.spec.schema import ApiSpec
from cspm_collector.storage.records import ResourceRecord

from .base import register
from .generic import Entry, GenericCollector

# root list API -> (API listing inline policy names, API returning one inline document, id parameter)
_INLINE = {
    "list_users": ("list_user_policies", "get_user_policy", "UserName"),
    "list_roles": ("list_role_policies", "get_role_policy", "RoleName"),
    "list_groups": ("list_group_policies", "get_group_policy", "GroupName"),
}


_REPORT_APIS = frozenset({"generate_credential_report", "get_credential_report"})


@register("iam")
class IamCollector(GenericCollector):
    """Second-level lookups that a single ``depends_on`` level cannot express:

    * inline policy documents (names come from ``list_*_policies``)
    * ``get_access_key_last_used`` for every access key of a user
    """

    def enrich(self, root: ApiSpec, entry: Entry) -> None:
        inline = _INLINE.get(root.api)
        if inline:
            list_api, get_api, id_param = inline
            names = (entry.details.get(list_api) or {}).get("PolicyNames", [])
            docs = {}
            for name in names:
                res = self.call(get_api, {id_param: entry.rid, "PolicyName": name}, self.ctx.client())
                if res.ok and res.pages:
                    docs[name] = res.pages[0]
                else:
                    entry.errors[f"{get_api}:{name}"] = res.error_code
            if names:
                entry.details[get_api] = docs
        if root.api == "list_users":
            keys = (entry.details.get("list_access_keys") or {}).get("AccessKeyMetadata", [])
            used = {}
            for key in keys:
                res = self.call("get_access_key_last_used", {"AccessKeyId": key["AccessKeyId"]}, self.ctx.client())
                if res.ok and res.pages:
                    used[key["AccessKeyId"]] = res.pages[0].get("AccessKeyLastUsed")
                else:
                    entry.errors[f"get_access_key_last_used:{key['AccessKeyId']}"] = res.error_code
            if keys:
                entry.details["get_access_key_last_used"] = used

    # ---------------------------------------------------------------- credential report
    def handled_elsewhere(self, api: ApiSpec) -> bool:
        return api.api in _REPORT_APIS

    def after_roots(self) -> None:
        if not _REPORT_APIS <= {a.api for a in self.ctx.service.apis}:
            return
        client = self.ctx.client()
        deadline = time.monotonic() + self.ctx.options.poll_timeout
        while True:
            res = self.call("generate_credential_report", {}, client, paginate=False)
            if not res.ok:
                return
            if res.pages[0].get("State") == "COMPLETE":
                break
            if time.monotonic() >= deadline:
                agg = self._aggs["generate_credential_report"]
                agg.failures[Status.TIMEOUT] += 1
                agg.first_error = ("ReportTimeout", "credential report not ready before the timeout")
                return
            time.sleep(self.ctx.options.poll_interval)

        res = self.call("get_credential_report", {}, client, paginate=False)
        if not res.ok or not res.pages:
            return
        page = res.pages[0]
        content = page.get("Content", b"")
        text = content.decode("utf-8") if isinstance(content, (bytes, bytearray)) else str(content)
        rows = list(csv.DictReader(io.StringIO(text)))
        self._aggs["get_credential_report"].count = len(rows)
        generated = page.get("GeneratedTime")
        for row in rows:
            self.result.resources.append(ResourceRecord(
                account_id=self.ctx.account_id, region=self.ctx.region, service="iam",
                resource_type="credential_report_row", resource_id=row["user"],
                config={**row, "_generated_time": generated}, arn=row.get("arn"),
            ))

    def tags_for(self, root: ApiSpec, entry: Entry):
        """list_users/list_roles omit tags; get_user/get_role (declared as detail calls) return them."""
        user = (entry.details.get("get_user") or {}).get("User", {})
        role = (entry.details.get("get_role") or {}).get("Role", {})
        return entry.item.get("Tags") or user.get("Tags") or role.get("Tags")
