"""User-made groups of collection items and of accounts, and how a selection of accounts is resolved.

A group is a named list of members (item names or account ids). It is only a shortcut for selecting things: a schedule
or a run that names a group follows the group as it is *now*, so adding an account to a group also adds it to the
schedules that use the group.
"""
from __future__ import annotations

import csv
import io
import re
import uuid
from datetime import datetime
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cspm_collector.core.config import AccountSettings
from cspm_collector.storage.store import Store

from .state import naive_utc

KINDS = ("items", "accounts")
ENV_PREFIX = "env:"  # built-in account groups: every account whose ``env`` label matches (not stored)


class GroupError(ValueError):
    """Bad group request; the message is shown to the user."""


FORMULA_MESSAGE = "이름은 =, +, -, @ 로 시작하거나 줄바꿈을 넣을 수 없습니다 (CSV를 엑셀로 열 때 수식으로 실행될 수 있습니다)"


def formula_like(name: str) -> bool:
    """A spreadsheet runs a cell that starts with = + - @ as a formula; names go into exported CSV files."""
    return bool(name) and (name[0] in "=+-@\t\r" or "\r" in name or "\n" in name)


class GroupCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    name: str = Field(min_length=1, max_length=40)
    members: list[str] = []

    @field_validator("name")
    @classmethod
    def _safe_name(cls, v: str) -> str:
        if formula_like(v.strip()):
            raise ValueError(FORMULA_MESSAGE)
        return v


class GroupUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, min_length=1, max_length=40)

    @field_validator("name")
    @classmethod
    def _safe_name(cls, v: str | None) -> str | None:
        if v is not None and formula_like(v.strip()):
            raise ValueError(FORMULA_MESSAGE)
        return v

    members: list[str] | None = None  # replaces the whole list
    add: list[str] = []
    remove: list[str] = []


class Target(BaseModel):
    """Which accounts a schedule or run is for. Empty = every configured account."""

    model_config = ConfigDict(extra="forbid")

    accounts: list[str] = []
    account_groups: list[str] = []

    def is_all(self) -> bool:
        return not self.accounts and not self.account_groups


def unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(v.strip() for v in values if v and v.strip()))


class Groups:
    def __init__(self, store: Store):
        self.store = store

    def list(self, kind: str | None = None) -> list[dict]:
        query = {"kind": kind} if kind else {}
        return sorted(self.store.coll("groups").find(query), key=lambda g: (g["kind"], g["name"].lower()))

    def get(self, group_id: str) -> dict | None:
        return self.store.coll("groups").find_one({"_id": group_id})

    def create(self, body: GroupCreate, valid_members: set[str], user: str, now: datetime) -> dict:
        if body.kind not in KINDS:
            raise GroupError("그룹 종류는 items 또는 accounts 입니다")
        name = body.name.strip()
        if not name:
            raise GroupError("그룹 이름을 입력하세요")
        if self.store.coll("groups").find_one({"kind": body.kind, "name": name}):
            raise GroupError(f"같은 이름의 그룹이 이미 있습니다: {name}")
        doc = {"_id": uuid.uuid4().hex[:12], "kind": body.kind, "name": name,
               "members": self._checked(body.members, valid_members), "created_at": naive_utc(now),
               "updated_at": naive_utc(now), "updated_by": user}
        self.store.coll("groups").insert_one(doc)
        return doc

    def update(self, group_id: str, body: GroupUpdate, valid_members: set[str], user: str, now: datetime) -> dict:
        doc = self.get(group_id)
        if not doc:
            raise KeyError(group_id)
        if body.name is not None:
            name = body.name.strip()
            clash = self.store.coll("groups").find_one({"kind": doc["kind"], "name": name, "_id": {"$ne": group_id}})
            if not name or clash:
                raise GroupError("이름이 비었거나 같은 이름의 그룹이 있습니다")
            doc["name"] = name
        members = list(doc["members"]) if body.members is None else self._checked(body.members, valid_members)
        members = [m for m in members if m not in set(body.remove)]
        members = unique([*members, *self._checked(body.add, valid_members)])
        doc.update(members=members, updated_at=naive_utc(now), updated_by=user)
        self.store.coll("groups").replace_one({"_id": group_id}, doc)
        return doc

    def delete(self, group_id: str) -> dict | None:
        doc = self.get(group_id)
        if doc:
            self.store.coll("groups").delete_one({"_id": group_id})
        return doc

    @staticmethod
    def _checked(members: list[str], valid: set[str]) -> list[str]:
        members = unique(members)
        unknown = [m for m in members if m not in valid]
        if unknown:
            raise GroupError(f"알 수 없는 항목: {', '.join(unknown)}")
        return members

    def remove_account(self, account_id: str) -> list[str]:
        """Drop a deleted account from every account group; returns the names of the groups that held it."""
        names = []
        for g in self.list("accounts"):
            if account_id in g["members"]:
                self.store.coll("groups").update_one({"_id": g["_id"]}, {"$pull": {"members": account_id}})
                names.append(g["name"])
        return names

    # ------------------------------------------------------------------ resolving
    def env_groups(self, accounts: list[AccountSettings]) -> list[dict]:
        envs = sorted({a.env for a in accounts if a.env})
        return [{"_id": ENV_PREFIX + e, "kind": "accounts", "name": f"{e} 전체", "builtin": True,
                 "members": [a.account_id for a in accounts if a.env == e]} for e in envs]

    def resolve_accounts(self, target: Target, accounts: list[AccountSettings]) -> list[str] | None:
        """Account ids a run should cover; ``None`` means all configured accounts. Unknown ids/groups raise."""
        if target.is_all():
            return None
        known = {a.account_id for a in accounts}
        by_id = {g["_id"]: g for g in [*self.env_groups(accounts), *self.list("accounts")]}
        picked = list(target.accounts)
        for gid in target.account_groups:
            if gid not in by_id:
                raise GroupError(f"알 수 없는 어카운트 그룹: {gid}")
            picked += by_id[gid]["members"]
        picked = unique(picked)
        unknown = [a for a in picked if a not in known]
        if unknown:
            raise GroupError(f"설정에 없는 어카운트: {', '.join(unknown)}")
        if not picked:
            raise GroupError("선택한 어카운트가 없습니다 (빈 그룹)")
        return picked

    def resolve_items(self, group_ids: list[str]) -> list[str]:
        out: list[str] = []
        for gid in group_ids:
            doc = self.get(gid)
            if not doc or doc["kind"] != "items":
                raise GroupError(f"알 수 없는 항목 그룹: {gid}")
            out += doc["members"]
        return unique(out)


# ----------------------------------------------------------------------------- CSV import
GROUP_CSV_COLUMNS = ("kind", "name", "members", "action")
ACTIONS = {"set": "set", "replace": "set", "add": "add", "remove": "remove", "delete": "delete",
           "교체": "set", "추가": "add", "제거": "remove", "삭제": "delete", "": "set"}
KIND_ALIASES = {"items": "items", "item": "items", "항목": "items", "accounts": "accounts", "account": "accounts", "어카운트": "accounts"}
MAX_GROUP_ROWS = 500


def _split(cell: str) -> list[str]:
    return unique(re.split(r"[\s;|,]+", cell))


def plan_group_csv(text: str, current: list[dict], valid: dict[str, set[str]], used_by: dict[str, int]) -> list[dict]:
    """Dry-run a groups CSV against the current groups: one result row per CSV line, nothing is changed.

    Columns ``kind`` (items/accounts), ``name``, ``members`` (space, ``;`` or ``|`` separated) and ``action``:
    ``set`` (default: create the group or replace its members), ``add`` / ``remove`` (change members of an existing
    group), ``delete``. Rows are applied in order, so later rows see the effect of earlier ones.
    Each result: ``{line, kind, name, action, op, members, message, error}``; ``op`` is what to do (create / replace /
    add / remove / delete) or None when ``error`` is set. ``used_by``: group id -> schedules naming it."""
    text = text.lstrip("﻿")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        raise GroupError("헤더와 한 줄 이상의 데이터가 필요합니다")
    if len(lines) - 1 > MAX_GROUP_ROWS:
        raise GroupError(f"한 번에 {MAX_GROUP_ROWS}줄까지 가져올 수 있습니다")
    delim = max((",", "\t", ";"), key=lines[0].count)
    reader = csv.reader(io.StringIO("\n".join(lines)), delimiter=delim)
    header = [h.strip().lower() for h in next(reader)]
    unknown = [h for h in header if h not in GROUP_CSV_COLUMNS]
    if unknown:
        raise GroupError(f"알 수 없는 열: {', '.join(unknown)} (사용 가능: {', '.join(GROUP_CSV_COLUMNS)})")
    if "kind" not in header or "name" not in header:
        raise GroupError("kind, name 열이 필요합니다")
    if len(set(header)) != len(header):
        raise GroupError("같은 열이 두 번 있습니다")
    state = {(g["kind"], g["name"]): list(g["members"]) for g in current if not g.get("builtin")}
    ids = {(g["kind"], g["name"]): g["_id"] for g in current if not g.get("builtin")}
    builtin = {g["name"] for g in current if g.get("builtin")}
    out = []
    for n, cells in enumerate(reader, start=2):
        cells = [c.strip() for c in cells]
        while len(cells) > len(header) and not cells[-1]:
            cells.pop()
        raw = dict(zip(header, cells))
        row = {"line": n, "kind": KIND_ALIASES.get(raw.get("kind", "").lower(), raw.get("kind", "")), "name": raw.get("name", ""),
               "action": ACTIONS.get(raw.get("action", "").lower(), raw.get("action", "")), "members": _split(raw.get("members", "")),
               "message": "", "error": None, "op": None}
        out.append(row)
        key = (row["kind"], row["name"])
        if len(cells) > len(header):
            row["error"] = "열이 헤더보다 많습니다 (쉼표가 들어간 값은 따옴표로 감싸세요)"
        elif row["kind"] not in KINDS:
            row["error"] = "kind는 items 또는 accounts 입니다"
        elif not row["name"] or len(row["name"]) > 40:
            row["error"] = "그룹 이름은 1~40자입니다"
        elif formula_like(row["name"]):
            row["error"] = FORMULA_MESSAGE
        elif row["name"] in builtin and row["kind"] == "accounts":
            row["error"] = "자동 그룹(env)은 바꿀 수 없습니다"
        elif row["action"] not in ("set", "add", "remove", "delete"):
            row["error"] = "action은 set, add, remove, delete 중 하나입니다"
        else:
            bad = [m for m in row["members"] if m not in valid[row["kind"]]]
            exists = key in state
            if bad:
                row["error"] = f"알 수 없는 멤버: {', '.join(bad)}"
            elif row["action"] == "set":
                row["op"] = "replace" if exists else "create"
                state[key] = row["members"]
            elif not exists:
                row["error"] = "없는 그룹입니다 (set으로 먼저 만드세요)"
            elif row["action"] == "delete":
                row["op"] = "delete"
                if used_by.get(ids.get(key, ""), 0):
                    row["message"] = f"자동 수집 {used_by[ids[key]]}개가 이 그룹을 대상으로 쓰고 있어 삭제하면 건너뜁니다"
                del state[key]
            elif not row["members"]:
                row["error"] = "members가 비어 있습니다"
            else:
                row["op"] = row["action"]
                state[key] = (unique([*state[key], *row["members"]]) if row["action"] == "add"
                              else [m for m in state[key] if m not in set(row["members"])])
    return out


def group_csv(groups: list[dict]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(GROUP_CSV_COLUMNS)
    for g in groups:
        if not g.get("builtin"):
            w.writerow([g["kind"], g["name"], " ".join(g["members"]), "set"])
    return out.getvalue()
