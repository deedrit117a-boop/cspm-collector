"""Pydantic models for ``collect_spec.yaml``."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DependsOn(BaseModel):
    """Call this API once per item returned by a parent API.

    ``params`` maps this API's request parameter -> field name in the parent item.
    """

    model_config = ConfigDict(extra="forbid")

    api: str
    params: dict[str, str] = Field(default_factory=dict)


class ApiSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api: str
    alias: str | None = None  # unique name inside the service when the same API is called twice
    client: str | None = None  # overrides ServiceSpec.client (e.g. s3control, logs)
    paginate: bool = False
    parameters: dict = Field(default_factory=dict)
    result_path: str | None = None  # key holding the resource list; None = whole response
    resource_type: str | None = None
    id_field: str | None = None  # "a+b" joins the non-empty fields with "|" when one is not unique on its own
    arn_field: str | None = None  # item field holding the ARN (default: Arn / ARN)
    # "<dependent api key>.<path>": take the tags from a detail response, e.g. "list_resource_tags.Tags"
    tags_from: str | None = None
    arn_from: str | None = None  # same syntax: take the ARN from a detail response, e.g. "describe_cluster.cluster.arn"
    depends_on: DependsOn | None = None
    # A dependent API whose items are resources of their own (listeners of a load balancer, records of a zone)
    # instead of detail attached to the parent. Needs result_path + resource_type.
    as_resource: bool = False
    inherit: dict[str, str] = Field(default_factory=dict)  # stored field -> parent item field (e.g. hosted_zone_id: Id)
    scope_id_to_parent: bool = False  # prefix the id with the parent id (ids unique only within the parent)
    setting: str | None = None  # store the response in account_settings under this name, not as a resource
    # secret-bearing values to mask in this API's items / detail response, see collectors/masking.py
    mask: list[str] = Field(default_factory=list)
    # List-item field that changes whenever the resource's details change (Lambda LastModified, CloudFront LastModifiedTime):
    # while it is the same as in the stored copy, the detail calls are not repeated (re-read anyway every ``full_refresh_days`` days).
    change_marker: str | None = None
    opt_in_flag: str | None = None  # CLI flag that must be set to call this API
    needs_review: bool = False  # set by the generator when a value was guessed
    note: str | None = None

    @property
    def key(self) -> str:
        """Identity inside the service: what ``depends_on`` points at and what status rows are named."""
        return self.alias or self.api


class ServiceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: str
    client: str  # boto3 client name
    scope: Literal["global", "regional"] = "regional"
    enabled: bool = True
    tier: Literal[1, 2, 3] = 3
    collector: str = "generic"  # "generic" or the name of a custom collector
    rule_count: int = 0
    # API whose "SUCCESS with at least one item" means the service is enabled in the region;
    # stored as the account setting "<service>_enablement".
    enablement_api: str | None = None
    # Region whose endpoint serves a global-scope service (default us-east-1); e.g. Global Accelerator: us-west-2
    api_region: str | None = None
    apis: list[ApiSpec] = Field(default_factory=list)


class CollectSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spec_version: str
    prowler_version: str | None = None
    source_hash: str | None = None
    services: list[ServiceSpec]
