"""Auto Scaling: launch configurations carry UserData, which is masked like EC2's."""
from __future__ import annotations

from cspm_collector.core.secrets import mask_user_data
from cspm_collector.spec.schema import ApiSpec

from .base import register
from .ec2 import SCAN_FLAG
from .generic import Entry, GenericCollector


@register("autoscaling")
class AutoScalingCollector(GenericCollector):
    def sanitize_item(self, root: ApiSpec, entry: Entry) -> None:
        if root.api == "describe_launch_configurations" and entry.item.get("UserData"):
            entry.item["UserData"], hits = mask_user_data(
                entry.item["UserData"], SCAN_FLAG in self.ctx.options.flags, f"launch_configuration.{entry.rid}.UserData")
            entry.findings += hits
