"""Route 53: zone ids without the "/hostedzone/" prefix, ARNs, zone tags. Records are separate documents
(spec: as_resource) so large zones never approach the 16MB document limit."""
from __future__ import annotations

from cspm_collector.spec.schema import ApiSpec

from .base import register
from .generic import Entry, GenericCollector

_PREFIXES = {"hosted_zone": "/hostedzone/", "health_check": "/healthcheck/"}
_ARN = {"hosted_zone": "hostedzone", "health_check": "healthcheck"}


@register("route53")
class Route53Collector(GenericCollector):
    def _base_id(self, root: ApiSpec, item: dict) -> str:
        rid = super()._base_id(root, item)
        prefix = _PREFIXES.get(root.resource_type or "")
        return rid[len(prefix):] if prefix and rid.startswith(prefix) else rid

    def arn_for(self, root: ApiSpec, entry: Entry):
        kind = _ARN.get(root.resource_type or "")
        return f"arn:aws:route53:::{kind}/{entry.rid}" if kind else super().arn_for(root, entry)

    def enrich(self, root: ApiSpec, entry: Entry) -> None:
        if root.resource_type == "hosted_zone":
            res = self.call("list_tags_for_resource", {"ResourceType": "hostedzone", "ResourceId": entry.rid},
                            self.ctx.client())
            if res.ok and res.pages:
                entry.details["list_tags_for_resource"] = res.pages[0]
            elif not res.ok:
                entry.errors["list_tags_for_resource"] = res.error_code

    def tags_for(self, root: ApiSpec, entry: Entry):
        return ((entry.details.get("list_tags_for_resource") or {}).get("ResourceTagSet") or {}).get("Tags")
