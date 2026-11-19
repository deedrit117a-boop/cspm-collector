"""Connection check of an AWS account: can the collector open it, and is it really that account?

For each account the check does what a collection does first, and nothing else (read-only, two cheap STS calls):
it builds the account's session (AWS profile and/or role), asks ``sts:GetCallerIdentity`` and compares the account.
Every failure is turned into a short code, a plain message and a hint for the fix, so that dozens of accounts can be
checked at once and the reasons told apart (SSO login needed / role refused / wrong account / ...).
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable

import botocore.exceptions as bex
from botocore.config import Config

from cspm_collector.core.config import AccountSettings
from cspm_collector.core.session import DEFAULT_REGION, AccountMismatch, AccountSession, retry_file_race
from cspm_collector.storage.store import Store

from .accounts import available_profiles

CHECK_WORKERS = 8
# no long retry chains: a check must tell quickly that something is wrong
CHECK_CONFIG = Config(retries={"mode": "standard", "max_attempts": 2}, connect_timeout=5, read_timeout=20,
                      user_agent_extra="cspm-collector-check")

OK = "OK"
LABELS = {
    "OK": "정상",
    "PROFILE_MISSING": "프로필 없음",
    "SSO_LOGIN_NEEDED": "SSO 로그인 필요",
    "CREDENTIALS_EXPIRED": "자격증명 만료",
    "EXTERNAL_ID_ENV_MISSING": "ExternalId 환경변수 없음",
    "ASSUME_DENIED": "Role을 맡을 수 없음",
    "ACCOUNT_MISMATCH": "다른 어카운트",
    "NETWORK": "네트워크 오류",
    "ERROR": "오류",
}


def _name(exc: Exception) -> str:
    return type(exc).__name__


def classify(exc: Exception, acct: AccountSettings) -> tuple[str, str, str]:
    """``(code, message, hint)`` for the exception a check ran into."""
    prof = acct.profile
    if isinstance(exc, bex.ProfileNotFound):
        return ("PROFILE_MISSING", f"이 서버의 AWS 설정에 프로필 {prof}이(가) 없습니다.",
                "~/.aws/config에 SSO 프로필을 추가하거나 어카운트의 AWS 프로필 이름을 고치세요.")
    if _name(exc) in ("SSOTokenLoadError", "UnauthorizedSSOTokenError", "TokenRetrievalError", "SSOError") or "SSO" in str(exc) and "token" in str(exc).lower():
        return ("SSO_LOGIN_NEEDED", f"SSO 로그인 정보가 없거나 만료되었습니다{f' (프로필 {prof})' if prof else ''}.",
                f"터미널에서 `aws sso login{f' --profile {prof}' if prof else ''}`을 실행한 뒤 다시 확인하세요.")
    if isinstance(exc, bex.NoCredentialsError) or _name(exc) == "CredentialRetrievalError":
        return ("SSO_LOGIN_NEEDED", "사용할 AWS 자격증명이 없습니다.",
                "서버를 시작한 셸에서 AWS_PROFILE을 지정하거나 어카운트에 AWS 프로필을 설정하고, SSO 로그인을 하세요.")
    if isinstance(exc, RuntimeError) and "is not set" in str(exc) and "env var" in str(exc):
        return ("EXTERNAL_ID_ENV_MISSING", f"ExternalId를 담은 환경변수 {acct.external_id_env}이(가) 서버에 설정되어 있지 않습니다.",
                "Role이 ExternalId를 요구하지 않으면 어카운트의 ExternalId 칸을 비우고, 요구하면 서버를 시작하는 셸에 그 환경변수를 설정하세요.")
    if isinstance(exc, AccountMismatch):
        return ("ACCOUNT_MISMATCH", str(exc), "프로필이나 Role이 이 어카운트를 가리키는지 확인하세요.")
    if isinstance(exc, bex.ClientError):
        error = exc.response.get("Error", {})
        code, op = error.get("Code", ""), exc.operation_name
        if code in ("ExpiredToken", "ExpiredTokenException", "RequestExpired", "InvalidClientTokenId", "UnrecognizedClientException"):
            return ("CREDENTIALS_EXPIRED", "자격증명이 만료되었거나 유효하지 않습니다.",
                    f"`aws sso login{f' --profile {prof}' if prof else ''}`로 다시 로그인하세요.")
        if op == "AssumeRole" and code == "AccessDenied":
            return ("ASSUME_DENIED", "Role을 맡을 수 없습니다 (AccessDenied).",
                    "다음 중 하나입니다: ① 그 어카운트에 Role이 없음 ② Role의 신뢰 정책이 이 신원을 허용하지 않음 "
                    "③ 내 권한에 sts:AssumeRole이 없음 ④ ExternalId가 맞지 않음. 어카운트에서 `aws iam get-role`로 Role과 신뢰 정책을 확인하세요.")
        return ("ERROR", f"{code or _name(exc)}: {error.get('Message', str(exc))}"[:300], "")
    if isinstance(exc, (bex.EndpointConnectionError, bex.ConnectTimeoutError, bex.ReadTimeoutError, bex.SSLError)):
        return ("NETWORK", f"AWS에 연결하지 못했습니다 ({_name(exc)}).",
                "프록시/네트워크와 AWS_CA_BUNDLE(사내 인증서) 설정을 확인하세요.")
    return ("ERROR", f"{_name(exc)}: {exc}"[:300], "")


def check_account(acct: AccountSettings, profiles: set[str] | None = None) -> dict:
    """Run the check for one account; never raises. The result has no secrets (an ARN and an account id at most)."""
    began = time.perf_counter()
    out: dict = {"account_id": acct.account_id, "name": acct.name, "code": OK, "ok": True, "message": "", "hint": "",
                 "caller_arn": None, "actual_account": None}
    try:
        if acct.profile and profiles is not None and acct.profile not in profiles:
            raise bex.ProfileNotFound(profile=acct.profile)
        sess = AccountSession(acct, client_config=CHECK_CONFIG)
        if acct.role_arn:  # who am I before the role: tells whose identity tries to open the account
            out["my_arn"] = retry_file_race(
                lambda: sess._base.client("sts", region_name=DEFAULT_REGION, config=CHECK_CONFIG).get_caller_identity())["Arn"]
        ident = sess.caller_identity()
        out["caller_arn"], out["actual_account"] = ident["Arn"], ident["Account"]
        if ident["Account"] != acct.account_id:
            sess.verify_identity()  # raises AccountMismatch with the explanation
    except Exception as exc:  # noqa: BLE001 - every failure becomes a result row
        code, message, hint = classify(exc, acct)
        out.update(code=code, ok=False, message=message, hint=hint)
        if code == "ASSUME_DENIED" and out.get("my_arn"):
            out["message"] += f" 내 신원: {out['my_arn']}"
    out["label"] = LABELS.get(out["code"], out["code"])
    out["ms"] = round((time.perf_counter() - began) * 1000)
    out["at"] = datetime.now(timezone.utc).replace(tzinfo=None)
    return out


class CheckRunner:
    """Runs a batch of checks in the background (one batch at a time) and keeps the latest result of every account in
    the database, so the page shows it after a reload and from any server."""

    def __init__(self, store: Store, load_accounts: Callable[[], list[AccountSettings]],
                 check: Callable[..., dict] = check_account, profiles: Callable[[], set[str]] = available_profiles,
                 workers: int = CHECK_WORKERS):
        self.store, self._load_accounts, self._check, self._profiles, self.workers = store, load_accounts, check, profiles, workers
        self._lock = threading.Lock()
        self._job: dict | None = None
        self._thread: threading.Thread | None = None

    def results(self) -> dict[str, dict]:
        doc = self.store.coll("runtime").find_one({"_id": "account_checks"})
        return dict((doc or {}).get("results") or {})

    def job(self) -> dict | None:
        with self._lock:
            return dict(self._job) if self._job else None

    def start(self, account_ids: list[str] | None, user: str) -> tuple[dict, bool]:
        """Returns ``(job, started)``; a batch that is still running is returned as it is (``started`` False)."""
        with self._lock:
            if self._job and self._job["state"] == "running":
                return dict(self._job), False
            known = {a.account_id: a for a in self._load_accounts()}
            wanted = [known[i] for i in (account_ids if account_ids is not None else known) if i in known]
            self._job = {"state": "running", "total": len(wanted), "done": 0, "ok": 0, "failed": 0, "by": user,
                         "started_at": datetime.now(timezone.utc).replace(tzinfo=None), "finished_at": None}
            self._thread = threading.Thread(target=self._run, args=(wanted,), name="cspm-checks", daemon=True)
            self._thread.start()
            return dict(self._job), True

    def wait(self, timeout: float = 30.0) -> bool:  # for tests
        t = self._thread
        if t:
            t.join(timeout)
        return not (t and t.is_alive())

    def _run(self, accounts: list[AccountSettings]) -> None:
        profiles = self._profiles()
        coll = self.store.coll("runtime")

        def one(acct: AccountSettings) -> None:
            try:
                res = self._check(acct, profiles)
            except Exception as exc:  # noqa: BLE001 - one broken check must neither stop the batch nor stay unreported
                code, message, hint = classify(exc, acct)
                res = {"account_id": acct.account_id, "name": acct.name, "ok": False, "code": code, "message": message, "hint": hint,
                       "label": LABELS.get(code, code), "at": datetime.now(timezone.utc).replace(tzinfo=None)}
            coll.update_one({"_id": "account_checks"}, {"$set": {f"results.{acct.account_id}": res}}, upsert=True)
            with self._lock:
                self._job["done"] += 1
                self._job["ok" if res.get("ok") else "failed"] += 1

        try:
            with ThreadPoolExecutor(max_workers=max(1, min(self.workers, len(accounts) or 1))) as pool:
                list(pool.map(one, accounts))
        finally:
            with self._lock:
                self._job["state"] = "done"
                self._job["finished_at"] = datetime.now(timezone.utc).replace(tzinfo=None)
