"""EC2: generic collection plus UserData masking."""
from __future__ import annotations

from cspm_collector.core.secrets import mask_user_data
from cspm_collector.spec.schema import ApiSpec

from .base import register
from .generic import Entry, GenericCollector

SCAN_FLAG = "--collect-userdata"


@register("ec2")
class Ec2Collector(GenericCollector):
    """UserData may hold credentials: it is always masked, and only scanned for secrets
    (location/type reported, never the content) when ``--collect-userdata`` is given."""

    def sanitize_detail(self, api: ApiSpec, value, entry: Entry):
        if not value:
            return value
        scan = SCAN_FLAG in self.ctx.options.flags
        if api.api == "describe_instance_attribute":
            ud = value.get("UserData")
            if isinstance(ud, dict):
                ud["Value"], hits = mask_user_data(ud.get("Value"), scan, f"instance.{entry.rid}.UserData")
                entry.findings += hits
        elif api.api == "describe_launch_template_versions":
            for i, ver in enumerate(value.get("LaunchTemplateVersions", [])):
                data = ver.get("LaunchTemplateData", {})
                if "UserData" in data:
                    data["UserData"], hits = mask_user_data(
                        data["UserData"], scan, f"launch_template.{entry.rid}.versions[{i}].UserData")
                    entry.findings += hits
        return value

    def tags_for(self, root: ApiSpec, entry: Entry):
        return entry.item.get("Tags") or entry.item.get("TagSet")
