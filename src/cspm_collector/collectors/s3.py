"""S3: buckets are listed once per account; per-bucket calls go to the bucket's own region."""
from __future__ import annotations

from cspm_collector.spec.schema import ApiSpec

from .base import register
from .generic import Entry, GenericCollector

_LOCATION_ALIASES = {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}


@register("s3")
class S3Collector(GenericCollector):
    def collect(self, ctx):
        self._regions: dict[str, str | None] = {}
        return super().collect(ctx)

    def prepare_entries(self, root: ApiSpec, entries: list[Entry]) -> None:
        if root.api != "list_buckets":
            return
        todo = []
        for e in entries:
            if e.item.get("BucketRegion"):
                self._regions[e.rid] = e.item["BucketRegion"]
            else:
                todo.append(e)

        def locate(e: Entry) -> None:
            res = self.call("get_bucket_location", {"Bucket": e.rid}, self.ctx.client("s3", "us-east-1"))
            if res.ok and res.pages:
                loc = res.pages[0].get("LocationConstraint")
                self._regions[e.rid] = _LOCATION_ALIASES.get(loc, loc)
            else:
                e.errors["get_bucket_location"] = res.error_code

        self._pmap(locate, todo)
        for e in entries:
            e.extra["resource_region"] = self._regions.get(e.rid)  # unknown stays None

    def client_for(self, api: ApiSpec, entry: Entry | None):
        if api is not None and api.depends_on and api.depends_on.api == "list_buckets" and entry is not None:
            region = self._regions.get(entry.rid)
            return self.ctx.client(api.client or "s3", region or "us-east-1")
        return super().client_for(api, entry)

    def arn_for(self, root: ApiSpec, entry: Entry):
        return f"arn:aws:s3:::{entry.rid}" if root.api == "list_buckets" else super().arn_for(root, entry)

    def tags_for(self, root: ApiSpec, entry: Entry):
        tagging = entry.details.get("get_bucket_tagging") or {}
        return tagging.get("TagSet")
