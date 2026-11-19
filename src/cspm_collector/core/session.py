"""AWS sessions: ambient credentials or AssumeRole with automatic refresh."""
from __future__ import annotations

import os
import random
import threading
import time
from typing import Callable, TypeVar

import boto3
import botocore.session
from botocore.config import Config
from botocore.credentials import DeferredRefreshableCredentials

from .config import AccountSettings

ROLE_SESSION_NAME = "cspm-collector"
DEFAULT_REGION = "us-east-1"  # STS / region discovery / global service endpoints


_REGIONS: dict[str, frozenset[str]] = {}


def region_supported(client: str, region: str) -> bool:
    """False only when botocore's endpoint data lists regions for ``client`` and ``region`` is not among them.

    Services that do not exist in a region have no endpoint there: calling them fails only after many slow
    connection retries (observed: 1-2 minutes per service). Unknown clients or empty data count as supported, so
    a service newer than the installed botocore is never skipped by mistake.
    """
    if client not in _REGIONS:
        try:
            _REGIONS[client] = frozenset(botocore.session.get_session().get_available_regions(client))
        except Exception:  # noqa: BLE001 - no data: do not guess
            _REGIONS[client] = frozenset()
    known = _REGIONS[client]
    return not known or region in known


def make_client_config(max_pool: int = 64) -> Config:
    return Config(
        retries={"mode": "adaptive", "max_attempts": 10},
        max_pool_connections=max_pool,
        connect_timeout=5,
        read_timeout=60,
        user_agent_extra="cspm-collector",
        # us-east-1 would otherwise use the global s3.amazonaws.com endpoint, which TLS-inspecting proxies
        # (e.g. Zscaler) re-sign with a CA that the bundled certificates do not know; regional ones verify fine.
        s3={"us_east_1_regional_endpoint": "regional"},
    )


T = TypeVar("T")


def retry_file_race(fn: Callable[[], T], tries: int = 6) -> T:
    """Run ``fn``; retry when the AWS SSO token cache file is busy.

    Profiles of one SSO session share one token file (``~/.aws/sso/cache``). When several accounts are opened at the
    same time and the token must be refreshed, they all rewrite that file; on Windows the replacement then fails
    with ``PermissionError``. The first one to finish leaves a fresh token, so waiting a moment and trying again works."""
    for attempt in range(tries):
        try:
            return fn()
        except PermissionError:
            if attempt == tries - 1:
                raise
            time.sleep(random.uniform(0.2, 0.9) * (attempt + 1))
    raise AssertionError("unreachable")  # pragma: no cover


class AccountMismatch(RuntimeError):
    """The credentials in use belong to another AWS account than the one being collected."""


class AccountSession:
    """One AWS account. Clients are cached per ``(service, region)`` and are thread-safe;
    creating them is serialized because ``boto3.Session`` is not."""

    def __init__(self, account: AccountSettings, base: boto3.Session | None = None, max_pool: int = 64,
                 client_config: Config | None = None):
        self.account = account
        self._base = base or (boto3.Session(profile_name=account.profile) if account.profile else boto3.Session())
        self._config = client_config or make_client_config(max_pool)
        self._lock = threading.Lock()
        self._clients: dict[tuple[str, str], object] = {}
        self._session = self._assume() if account.role_arn else self._base

    @property
    def account_id(self) -> str:
        return self.account.account_id

    def _assume(self) -> boto3.Session:
        params = {"RoleArn": self.account.role_arn, "RoleSessionName": ROLE_SESSION_NAME}
        if self.account.external_id_env:
            external_id = os.environ.get(self.account.external_id_env)
            if not external_id:
                raise RuntimeError(f"env var {self.account.external_id_env} is not set")
            params["ExternalId"] = external_id
        sts = self._base.client("sts", region_name=DEFAULT_REGION, config=self._config)

        def refresh() -> dict:
            creds = sts.assume_role(**params)["Credentials"]
            return {
                "access_key": creds["AccessKeyId"],
                "secret_key": creds["SecretAccessKey"],
                "token": creds["SessionToken"],
                "expiry_time": creds["Expiration"].isoformat(),
            }

        bs = botocore.session.get_session()
        bs._credentials = DeferredRefreshableCredentials(method="sts-assume-role", refresh_using=refresh)
        return boto3.Session(botocore_session=bs, region_name=DEFAULT_REGION)

    def caller_identity(self) -> dict:
        """``sts:GetCallerIdentity`` of this account's credentials (the first call also resolves them)."""
        return retry_file_race(lambda: self.client("sts").get_caller_identity())

    def verify_identity(self) -> str:
        """Refuse to collect when the credentials are not those of ``account_id``. Without this a missing
        ``role_arn`` would silently collect the *ambient* account and store it under the configured account's id."""
        actual = self.caller_identity()["Account"]
        if actual != self.account.account_id:
            if self.account.role_arn:
                how, hint = "맡은 Role", "role_arn이 다른 어카운트의 Role입니다."
            elif self.account.profile:
                how, hint = f"AWS 프로필 {self.account.profile}", "프로필이 다른 어카운트를 가리킵니다. 프로필 이름을 확인하세요."
            else:
                how, hint = "프로필과 Role 없이 쓰는 현재 AWS 자격증명", "이 어카운트의 AWS 프로필이나 role_arn을 설정하세요."
            raise AccountMismatch(f"{how}은 어카운트 {actual}의 것인데 설정된 어카운트는 {self.account.account_id}입니다. {hint}")
        return actual

    def client(self, service: str, region: str = DEFAULT_REGION):
        key = (service, region)
        with self._lock:
            if key not in self._clients:
                self._clients[key] = self._session.client(service, region_name=region, config=self._config)
            return self._clients[key]

    def enabled_regions(self, include_opt_in: bool = True) -> list[str]:
        """Regions enabled for this account (``describe_regions`` with AllRegions=False)."""
        resp = self.client("ec2").describe_regions(AllRegions=False)
        regions = resp["Regions"]
        if not include_opt_in:
            regions = [r for r in regions if r.get("OptInStatus") == "opt-in-not-required"]
        return sorted(r["RegionName"] for r in regions)

    def target_regions(self, include_opt_in: bool = True) -> list[str]:
        return list(self.account.regions) if self.account.regions else self.enabled_regions(include_opt_in)
