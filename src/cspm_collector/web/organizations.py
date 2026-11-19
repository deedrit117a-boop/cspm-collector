"""Accounts of an AWS Organization, to add them to the collector without typing every id.

Only the account list is read (``organizations:ListAccounts`` and ``DescribeOrganization``), with the server's own AWS
credentials: they must belong to the organization's management account (or a delegated administrator).
"""
from __future__ import annotations

import re
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .accounts import AccountBody

ROLE_NAME = re.compile(r"[\w+=,.@-]{1,64}")


class OrgError(RuntimeError):
    """The list could not be read; the message says why in terms the user can act on."""


class ImportOrgBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_ids: list[str] = Field(min_length=1, max_length=500)
    role_name: str  # the read-only role every account has (the collector assumes it in each account)
    env: str | None = None
    regions: list[str] | None = None  # empty = every enabled region (the region detection can fill it in later)
    external_id_env: str | None = None  # NAME of an environment variable

    @field_validator("role_name")
    @classmethod
    def _role(cls, v: str) -> str:
        v = v.strip().removeprefix("role/")
        if not ROLE_NAME.fullmatch(v):
            raise ValueError("Role 이름에는 영문, 숫자, + = , . @ - _ 만 쓸 수 있습니다 (arn이 아니라 이름만 적으세요)")
        return v


def list_organization_accounts() -> dict:
    """``{"organization": {...}, "accounts": [{account_id, name, email, status, joined}]}`` for the current credentials."""
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        client = boto3.client("organizations", region_name="us-east-1")  # the Organizations endpoint lives in us-east-1
        org = client.describe_organization()["Organization"]
        accounts = []
        for page in client.get_paginator("list_accounts").paginate():
            accounts += page["Accounts"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        hint = {"AccessDeniedException": "이 서버의 AWS 자격증명에 organizations:ListAccounts, DescribeOrganization 권한이 없거나 조직의 관리 계정이 아닙니다.",
                "AWSOrganizationsNotInUseException": "이 AWS 계정은 AWS Organizations에 속해 있지 않습니다."}.get(code)
        raise OrgError(hint or f"조직의 어카운트 목록을 읽지 못했습니다 ({code})") from exc
    except BotoCoreError as exc:
        raise OrgError(f"AWS에 연결하지 못했습니다: {type(exc).__name__} (SSO 로그인이 되어 있는지 확인하세요)") from exc
    return {"organization": {"id": org.get("Id"), "management_account_id": org.get("ManagementAccountId") or org.get("MasterAccountId")},
            "accounts": [{"account_id": a["Id"], "name": a.get("Name") or a["Id"], "email": a.get("Email"),
                          "status": a.get("State") or a.get("Status"), "joined": a.get("JoinedTimestamp")} for a in accounts]}


def clean_name(name: str) -> str:
    """A name the account form accepts (no leading = + - @ that a spreadsheet would run as a formula, at most 60 characters)."""
    name = name.strip().lstrip("=+-@\t\r ")
    return (name or "account")[:60]


def bodies(org_accounts: list[dict], body: ImportOrgBody) -> tuple[list[AccountBody], dict[str, str]]:
    """Account forms for the chosen ids; ids that are not active members of the organization are skipped with a reason."""
    by_id = {a["account_id"]: a for a in org_accounts}
    good, skipped = [], {}
    for aid in dict.fromkeys(body.account_ids):
        a = by_id.get(aid)
        if a is None:
            skipped[aid] = "조직에 없는 어카운트"
        elif a.get("status") not in ("ACTIVE", None):
            skipped[aid] = f"활성 상태가 아님 ({a['status']})"
        else:
            good.append(AccountBody(account_id=aid, name=clean_name(a["name"]), env=body.env or None,
                                    role_arn=f"arn:aws:iam::{aid}:role/{body.role_name}", regions=body.regions or None,
                                    external_id_env=body.external_id_env or None))
    return good, skipped


Lister = Callable[[], dict]
