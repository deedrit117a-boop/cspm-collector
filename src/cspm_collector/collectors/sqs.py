"""SQS: list_queues only returns URLs; the ARN and tags come from the per-queue calls."""
from __future__ import annotations

from cspm_collector.spec.schema import ApiSpec

from .base import register
from .generic import Entry, GenericCollector


@register("sqs")
class SqsCollector(GenericCollector):
    def arn_for(self, root: ApiSpec, entry: Entry):
        return ((entry.details.get("get_queue_attributes") or {}).get("Attributes") or {}).get("QueueArn")

    def tags_for(self, root: ApiSpec, entry: Entry):
        return (entry.details.get("list_queue_tags") or {}).get("Tags")
