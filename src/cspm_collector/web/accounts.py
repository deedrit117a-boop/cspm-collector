"""AWS accounts added from the control page.

They are kept in the database (``settings`` collection, document ``accounts``) and merged with the ``accounts`` of the
configuration file when the page and the collector read their settings. The file is never rewritten (it may hold
comments, and a second server would not see the change). An account of the file always wins over one of the page.
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from cspm_collector.core.config import AccountSettings
from cspm_collector.storage.store import Store

from .state import naive_utc

_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
_ROLE = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):role/[\w+=,.@/-]+$")


class AccountError(ValueError):
    """Bad account request; the message is shown to the user."""


class AccountBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_id: str
    name: str | None = Field(None, max_length=60)
    env: str | None = Field(None, max_length=20)
    profile: str | None = Field(None, max_length=64)  # AWS (SSO) profile whose credentials open this account
    role_arn: str | None = None  # role the collector assumes in this account; empty = the ambient credentials
    external_id_env: str | None = None  # NAME of an environment variable, never the value
    regions: list[str] | None = None  # empty/None = every enabled region

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        if v is not None and (v[0] in "=+-@\t\r" or any(c in v for c in "\r\n")):
            raise ValueError("이름은 =, +, -, @ 로 시작하거나 줄바꿈을 넣을 수 없습니다 (CSV를 엑셀로 열 때 수식으로 실행될 수 있습니다)")
        return v

    @field_validator("profile")
    @classmethod
    def _profile(cls, v: str | None) -> str | None:
        if v is not None and not re.fullmatch(r"[\w.@+-]{1,64}", v):
            raise ValueError("AWS 프로필 이름에는 영문, 숫자, - _ . @ + 만 쓸 수 있습니다")
        return v

    @field_validator("name", "env", "role_arn", "external_id_env", "profile", mode="before")
    @classmethod
    def _blank_is_none(cls, v):
        return v.strip() or None if isinstance(v, str) else v

    @field_validator("account_id")
    @classmethod
    def _account_id(cls, v: str) -> str:
        if not re.fullmatch(r"\d{12}", v.strip()):
            raise ValueError("계정 ID는 12자리 숫자입니다")
        return v.strip()

    @field_validator("env")
    @classmethod
    def _env(cls, v: str | None) -> str | None:
        if v is not None and not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", v):
            raise ValueError("환경(env)은 소문자, 숫자, -, _ 만 쓸 수 있습니다 (예: dev)")
        return v

    @field_validator("external_id_env")
    @classmethod
    def _extid(cls, v: str | None) -> str | None:
        if v is not None and not re.fullmatch(r"[A-Z_][A-Z0-9_]*", v):
            raise ValueError("ExternalId에는 값이 아니라 환경변수 이름(대문자, 숫자, _)을 적으세요")
        return v

    @field_validator("regions", mode="before")
    @classmethod
    def _regions(cls, v):
        if not v:
            return None
        v = list(dict.fromkeys(r.strip() for r in v if r and r.strip()))
        bad = [r for r in v if not _REGION.match(r)]
        if bad:
            raise ValueError(f"리전 이름이 올바르지 않습니다: {', '.join(bad)}")
        return v or None

    @model_validator(mode="after")
    def _role_belongs_to_the_account(self):
        if self.role_arn:
            m = _ROLE.match(self.role_arn)
            if not m:
                raise ValueError("role_arn 형식이 올바르지 않습니다 (arn:aws:iam::<12자리>:role/<이름>)")
            if m.group(1) != self.account_id:
                raise ValueError("role_arn의 어카운트 번호가 어카운트 ID와 다릅니다")
        if self.external_id_env and not self.role_arn:
            raise ValueError("external_id_env는 role_arn과 함께 써야 합니다")
        return self

    def to_settings(self) -> AccountSettings:
        return AccountSettings(**self.model_dump())


class WebAccounts:
    def __init__(self, store: Store):
        self.store = store

    def _doc(self) -> list[dict]:
        doc = self.store.coll("settings").find_one({"_id": "accounts"})
        return list(doc["items"]) if doc else []

    def list(self) -> list[AccountSettings]:
        return [AccountSettings(**a) for a in self._doc()]

    def _save(self, items: list[dict], user: str, now: datetime) -> None:
        self.store.coll("settings").update_one(
            {"_id": "accounts"}, {"$set": {"items": items, "updated_at": naive_utc(now), "updated_by": user}}, upsert=True)

    def add(self, body: AccountBody, taken: set[str], user: str, now: datetime) -> AccountSettings:
        if body.account_id in taken:
            raise AccountError(f"이미 등록된 어카운트입니다: {body.account_id}")
        self._save([*self._doc(), body.model_dump()], user, now)
        return body.to_settings()

    def update(self, account_id: str, body: AccountBody, user: str, now: datetime) -> AccountSettings:
        items = self._doc()
        if body.account_id != account_id:
            raise AccountError("어카운트 ID는 바꿀 수 없습니다. 삭제하고 다시 추가하세요")
        if not any(a["account_id"] == account_id for a in items):
            raise KeyError(account_id)
        self._save([body.model_dump() if a["account_id"] == account_id else a for a in items], user, now)
        return body.to_settings()

    def upsert_many(self, bodies: list[AccountBody], user: str, now: datetime) -> None:
        items = {a["account_id"]: a for a in self._doc()}
        for b in bodies:
            items[b.account_id] = b.model_dump()
        self._save(list(items.values()), user, now)

    def delete(self, account_id: str, user: str, now: datetime) -> bool:
        items = self._doc()
        kept = [a for a in items if a["account_id"] != account_id]
        if len(kept) == len(items):
            return False
        self._save(kept, user, now)
        return True


def merged(config_accounts: list[AccountSettings], web: list[AccountSettings]) -> list[AccountSettings]:
    """The file's accounts first, then the page's; an id that is in both keeps the file's entry."""
    seen = {a.account_id for a in config_accounts}
    return [*config_accounts, *(a for a in web if a.account_id not in seen)]


# ----------------------------------------------------------------------------- CSV import
# account ids of the example rows of the downloadable template: importing them as they are is a mistake
TEMPLATE_IDS = frozenset({"123456789012", "210987654321"})
CSV_COLUMNS = ("account_id", "name", "env", "profile", "role_arn", "external_id_env", "regions")
_ALIASES = {"aws_profile": "profile", "sso_profile": "profile", "id": "account_id", "account": "account_id", "accountid": "account_id", "region": "regions",
            "externalid_env": "external_id_env", "external_id": "external_id_env", "role": "role_arn"}
MAX_CSV_BYTES = 200_000
MAX_CSV_ROWS = 500


def available_profiles() -> set[str]:
    """Profiles of this machine's AWS config (``~/.aws/config`` / credentials) that the collector can use."""
    import botocore.session

    try:
        return set(botocore.session.Session().available_profiles)
    except Exception:  # noqa: BLE001 - no readable config: no profiles
        return set()


def _reason(exc: ValidationError) -> str:
    return "; ".join(e["msg"].removeprefix("Value error, ") for e in exc.errors())


def repair_excel_id(value: str, role_arn: str | None) -> tuple[str, str | None]:
    """Excel turns a 12-digit account id into ``1.24249E+11`` (or drops its leading zeros) when a CSV is opened and
    saved. The id inside the role ARN is intact, so a damaged id that *fits* that number is replaced by it.
    Returns ``(account_id, note)``; the note says what was repaired. Anything that does not fit stays as it is
    (and is then refused by the normal validation) - a real mismatch must never be "fixed" silently."""
    if re.fullmatch(r"\d{1,11}", value):
        # An account id always has 12 digits, so a shorter number can only have lost leading zeros: pad it.
        return value.zfill(12), f"Excel이 앞의 0을 지운 계정 ID({value})를 12자리({value.zfill(12)})로 복구했습니다"
    m = _ROLE.match(role_arn or "")
    if not m or re.fullmatch(r"\d{12}", value):
        return value, None
    arn_id = m.group(1)
    try:
        if re.fullmatch(r"\d(\.\d+)?[eE]\+?\d+", value):  # scientific notation: the number must round to the ARN id
            mantissa, exp = re.split(r"[eE]", value)
            decimals = len(mantissa.split(".")[1]) if "." in mantissa else 0
            unit = 10 ** (int(exp) - decimals)
            fits = abs(float(value) - int(arn_id)) <= unit / 2 + 1
        else:
            fits = False
    except ValueError:
        fits = False
    return (arn_id, f"Excel이 바꾼 계정 ID({value})를 Role ARN의 {arn_id}로 복구했습니다") if fits else (value, None)


def parse_csv(text: str, profiles: set[str] | None = None, use_profiles: bool = False) -> list[dict]:
    """Rows of the CSV as ``{"line", "body": AccountBody | None, "error": str | None}``.

    The first line is the header (columns in any order; unknown columns are refused). Comma, tab and semicolon
    delimiters are recognised (Excel / pasted cells). ``regions`` are separated by spaces, ``;`` or ``|``.

    ``use_profiles``: a row without ``profile`` whose ``name`` is the name of one of ``profiles`` (the machine's AWS
    profiles) gets that profile, and its ``role_arn``/``external_id_env`` are dropped (the profile already opens the
    account). The row's note says so."""
    text = text.lstrip("﻿")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        raise AccountError("헤더와 한 줄 이상의 데이터가 필요합니다")
    if len(lines) - 1 > MAX_CSV_ROWS:
        raise AccountError(f"한 번에 {MAX_CSV_ROWS}줄까지 가져올 수 있습니다")
    delim = max((",", "\t", ";"), key=lines[0].count)
    reader = csv.reader(io.StringIO("\n".join(lines)), delimiter=delim)
    header = [_ALIASES.get(h.strip().lower(), h.strip().lower()) for h in next(reader)]
    unknown = [h for h in header if h not in CSV_COLUMNS]
    if unknown:
        raise AccountError(f"알 수 없는 열: {', '.join(unknown)} (사용 가능: {', '.join(CSV_COLUMNS)})")
    if "account_id" not in header:
        raise AccountError("account_id 열이 필요합니다")
    if len(set(header)) != len(header):
        raise AccountError("같은 열이 두 번 있습니다")
    rows, seen = [], set()
    for n, cells in enumerate(reader, start=2):
        cells = [c.strip() for c in cells]
        while len(cells) > len(header) and not cells[-1]:  # a trailing delimiter (Excel) adds empty cells
            cells.pop()
        raw = dict(zip(header, cells))
        if len(cells) > len(header):
            rows.append({"line": n, "body": None, "error": "열이 헤더보다 많습니다 (쉼표가 들어간 값은 따옴표로 감싸세요)"})
            continue
        raw["regions"] = [r for r in re.split(r"[\s;|,]+", raw.get("regions", "")) if r]
        note = None
        if "account_id" in raw:
            short = raw["account_id"]
            raw["account_id"], note = repair_excel_id(short, raw.get("role_arn"))
            if note and raw.get("role_arn") and re.fullmatch(r"\d{1,11}", short):  # Excel stripped the same zeros inside the ARN
                raw["role_arn"] = raw["role_arn"].replace(f"::{short}:role/", f"::{raw['account_id']}:role/", 1)
        if use_profiles and profiles and not raw.get("profile") and raw.get("name") in profiles:
            dropped = " (Role은 쓰지 않음)" if raw.get("role_arn") else ""
            raw["profile"], raw["role_arn"], raw["external_id_env"] = raw["name"], "", ""
            note = (note + " · " if note else "") + f"같은 이름의 AWS 프로필 {raw['profile']}을 사용합니다{dropped}"
        if raw.get("account_id") in TEMPLATE_IDS:
            rows.append({"line": n, "body": None, "account_id": raw["account_id"],
                         "error": "양식의 예시 행입니다. 이 줄을 지우고 실제 계정 ID, 이름, 프로필을 넣으세요"})
            continue
        try:
            body = AccountBody(**{k: v for k, v in raw.items() if v != "" and v != []})
        except ValidationError as exc:
            rows.append({"line": n, "body": None, "error": _reason(exc), "account_id": raw.get("account_id", "")})
            continue
        if body.account_id in seen:
            rows.append({"line": n, "body": None, "error": "CSV 안에 같은 계정 ID가 또 있습니다", "account_id": body.account_id})
            continue
        seen.add(body.account_id)
        rows.append({"line": n, "body": body, "error": None, "account_id": body.account_id, "note": note})
    return rows


def to_csv(accounts: list[AccountSettings]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for a in accounts:
        w.writerow([a.account_id, a.name or "", a.env or "", a.profile or "", a.role_arn or "", a.external_id_env or "",
                    " ".join(a.regions or [])])
    return out.getvalue()
