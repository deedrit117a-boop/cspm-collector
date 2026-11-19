"""Runtime settings. Secrets come from the environment, never from the file."""
from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


class MongoSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    uri: str = "mongodb://localhost:27017"
    database: str = "cspm"
    batch_size: int = 500
    collection_prefix: str = ""  # e.g. "000_": every collection becomes 000_resources, 000_scans, ...
    escape_keys: bool = True  # escape '.' / leading '$' in field names (safe on MongoDB < 5.0)
    max_doc_bytes: int = 12_000_000  # resources larger than this keep their config in resource_chunks
    chunk_bytes: int = 4_000_000


class AccountSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_id: str
    name: str | None = None
    env: str | None = None  # label such as "dev" / "prod": the control page offers "all <env> accounts" as a group
    profile: str | None = None  # AWS (SSO) profile of ~/.aws/config whose credentials open this account; None -> ambient
    role_arn: str | None = None  # None -> use the ambient credentials
    external_id_env: str | None = None  # name of the env var holding the ExternalId
    regions: list[str] | None = None  # None -> all enabled regions


class ConcurrencySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = 32  # (account, region, service) tasks running at the same time
    per_account: int = 8  # ... of which at most this many for one account
    per_service: int = 4  # ... and at most this many of the same service
    per_resource: int = 8  # inside one task: detail calls per resource (bucket, role, ...) running at the same time


class AkamaiCollect(BaseModel):
    model_config = ConfigDict(extra="forbid")

    properties: bool = True  # PAPI: groups, contracts, properties, hostnames, rule trees
    appsec: bool = True
    network_lists: bool = True
    edge_dns: bool = False  # only needed when Akamai is the authoritative DNS


class AkamaiAccountSettings(BaseModel):
    """One Akamai API client. Credentials come from an .edgerc file or from environment variables
    (``<env_prefix>_HOST``, ``_CLIENT_TOKEN``, ``_CLIENT_SECRET``, ``_ACCESS_TOKEN``); never from this file."""

    model_config = ConfigDict(extra="forbid")

    name: str
    edgerc: str | None = None
    section: str = "default"
    env_prefix: str | None = None
    account_switch_key_env: str | None = None  # name of the env var holding the switch key
    collect: AkamaiCollect = Field(default_factory=AkamaiCollect)
    max_workers: int = 4
    requests_per_second: float = 1.5  # PAPI default limit is 100 requests/minute per account
    max_retries: int = 6


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spec_path: str = "spec/collect_spec.yaml"
    # Do not call a regional service in a region where botocore's endpoint data says it does not exist
    # (recorded as NOT_SUPPORTED instead of waiting for connection retries to fail).
    skip_unsupported_regions: bool = True
    # Check with sts:GetCallerIdentity that the credentials really belong to each configured account before
    # collecting; a mismatch (e.g. a missing role_arn) fails that account instead of storing another account's data.
    verify_account_identity: bool = True
    # Before a web run, check every account of it (``web/preflight.py``) and leave out the ones that cannot be opened, with the
    # reason (SSO login needed, role refused, ...), instead of letting each of them fail in the middle of the run.
    preflight_check: bool = True
    # After a run with failures, redo the transient ones (timeouts, throttling, errors) once, automatically.
    auto_retry: bool = True
    # How often (days) the control page looks again for regions that an account uses but has not listed in ``regions``
    # (the free region probes; needs working AWS credentials at that time). 0 = never.
    region_check_days: int = 7
    # Items whose list answer says when the resource last changed (spec ``change_marker``: Lambda, CloudFront) do not repeat the
    # per-resource detail calls while that marker is unchanged. Every ``full_refresh_days`` days they are read in full anyway.
    # Name of the SERVER environment variable that holds the chat webhook URL used for notifications (the URL itself is never
    # kept in a file or in the database). Notifications are switched on on the settings page.
    notify_webhook_env: str = "CSPM_NOTIFY_WEBHOOK"
    incremental_details: bool = True
    full_refresh_days: int = 7
    timezone: str = "Asia/Seoul"  # schedules of the control page are read in this timezone
    mongo: MongoSettings = Field(default_factory=MongoSettings)
    accounts: list[AccountSettings] = Field(default_factory=list)
    concurrency: ConcurrencySettings = Field(default_factory=ConcurrencySettings)
    akamai: list[AkamaiAccountSettings] = Field(default_factory=list)


def load_settings(path: str | Path | None = None) -> Settings:
    """Load YAML settings; ``MONGO_URI`` / ``MONGO_DATABASE`` env vars take precedence."""
    data: dict = {}
    if path:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    settings = Settings.model_validate(data)
    if os.environ.get("MONGO_URI"):
        settings.mongo.uri = os.environ["MONGO_URI"]
    if os.environ.get("MONGO_DATABASE"):
        settings.mongo.database = os.environ["MONGO_DATABASE"]
    if os.environ.get("MONGO_COLLECTION_PREFIX") is not None:
        settings.mongo.collection_prefix = os.environ["MONGO_COLLECTION_PREFIX"]
    return settings
