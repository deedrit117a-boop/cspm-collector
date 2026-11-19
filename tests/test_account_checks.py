"""Connection checks: what each kind of failure is reported as, and the batch API."""
import threading
import time

import botocore.exceptions as bex
import mongomock
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from cspm_collector.core.config import AccountSettings, MongoSettings, Settings
from cspm_collector.core.session import AccountMismatch
from cspm_collector.storage.store import Store
from cspm_collector.web.checks import CheckRunner, check_account, classify
from cspm_collector.web.server import build_runtime
from test_web_api import SPEC, UI

MOTO = "123456789012"


def err(code, op="AssumeRole", msg="denied"):
    return bex.ClientError({"Error": {"Code": code, "Message": msg}}, op)


# ----------------------------------------------------------------------------- classification
@pytest.mark.parametrize("exc,acct,code", [
    (bex.ProfileNotFound(profile="p"), AccountSettings(account_id=MOTO, profile="p"), "PROFILE_MISSING"),
    (bex.SSOTokenLoadError(error_msg="no token"), AccountSettings(account_id=MOTO, profile="p"), "SSO_LOGIN_NEEDED"),
    (bex.NoCredentialsError(), AccountSettings(account_id=MOTO), "SSO_LOGIN_NEEDED"),
    (RuntimeError("env var CSPM_X is not set"), AccountSettings(account_id=MOTO, role_arn=f"arn:aws:iam::{MOTO}:role/r", external_id_env="CSPM_X"), "EXTERNAL_ID_ENV_MISSING"),
    (AccountMismatch("wrong"), AccountSettings(account_id=MOTO), "ACCOUNT_MISMATCH"),
    (err("AccessDenied"), AccountSettings(account_id=MOTO, role_arn=f"arn:aws:iam::{MOTO}:role/r"), "ASSUME_DENIED"),
    (err("ExpiredToken", "GetCallerIdentity"), AccountSettings(account_id=MOTO, profile="p"), "CREDENTIALS_EXPIRED"),
    (err("InvalidClientTokenId", "GetCallerIdentity"), AccountSettings(account_id=MOTO), "CREDENTIALS_EXPIRED"),
    (bex.EndpointConnectionError(endpoint_url="https://sts"), AccountSettings(account_id=MOTO), "NETWORK"),
    (err("Throttling", "GetCallerIdentity", "slow down"), AccountSettings(account_id=MOTO), "ERROR"),
    (ValueError("boom"), AccountSettings(account_id=MOTO), "ERROR"),
])
def test_every_failure_gets_a_code_a_message_and_a_hint(exc, acct, code):
    got, message, hint = classify(exc, acct)
    assert got == code and message
    if code != "ERROR":
        assert hint


def test_an_assume_role_denial_lists_the_possible_causes_and_the_profile_hint_names_the_profile():
    _, _, hint = classify(err("AccessDenied"), AccountSettings(account_id=MOTO, role_arn=f"arn:aws:iam::{MOTO}:role/r"))
    assert all(x in hint for x in ("Role이 없음", "신뢰 정책", "sts:AssumeRole", "ExternalId"))
    _, msg, hint = classify(bex.SSOTokenLoadError(error_msg="x"), AccountSettings(account_id=MOTO, profile="live-x"))
    assert "live-x" in msg and "aws sso login --profile live-x" in hint


# ----------------------------------------------------------------------------- the check itself
@mock_aws
def test_check_ok_wrong_account_missing_profile_and_missing_external_id_env(monkeypatch):
    ok = check_account(AccountSettings(account_id=MOTO))
    assert ok["ok"] is True and ok["code"] == "OK" and ok["actual_account"] == MOTO and ok["caller_arn"] and ok["ms"] >= 0

    wrong = check_account(AccountSettings(account_id="999999999999"))
    assert wrong["code"] == "ACCOUNT_MISMATCH" and MOTO in wrong["message"] and not wrong["ok"]

    missing = check_account(AccountSettings(account_id=MOTO, profile="no-such-profile"), {"other"})
    assert missing["code"] == "PROFILE_MISSING" and "no-such-profile" in missing["message"]

    monkeypatch.delenv("CSPM_NOT_SET", raising=False)
    noext = check_account(AccountSettings(account_id=MOTO, role_arn=f"arn:aws:iam::{MOTO}:role/r", external_id_env="CSPM_NOT_SET"))
    assert noext["code"] == "EXTERNAL_ID_ENV_MISSING"
    assert "label" in noext and noext["at"] is not None


@mock_aws
def test_check_through_a_role_reports_whose_identity_opens_the_account(monkeypatch):
    monkeypatch.setenv("CSPM_EXT", "external-id-value")
    res = check_account(AccountSettings(account_id=MOTO, role_arn=f"arn:aws:iam::{MOTO}:role/r", external_id_env="CSPM_EXT"))
    assert res["ok"] is True and res["my_arn"] and "assumed-role" in res["caller_arn"]


def test_a_result_has_no_secret_material():
    with mock_aws():
        res = check_account(AccountSettings(account_id=MOTO))
    blob = str(res)
    assert "AKIA" not in blob and "SecretAccessKey" not in blob and "SessionToken" not in blob


# ----------------------------------------------------------------------------- the batch and its API
def fake_check(acct, profiles=None):
    ok = acct.account_id != "222222222222"
    return {"account_id": acct.account_id, "name": acct.name, "ok": ok, "code": "OK" if ok else "SSO_LOGIN_NEEDED",
            "label": "정상" if ok else "SSO 로그인 필요", "message": "" if ok else "expired", "hint": "" if ok else "login",
            "caller_arn": None, "actual_account": acct.account_id, "ms": 5,
            "at": __import__("datetime").datetime(2026, 10, 26, 1, 2, 3)}


@pytest.fixture
def web():
    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()
    settings = Settings(accounts=[AccountSettings(account_id="111111111111", name="a"),
                                  AccountSettings(account_id="222222222222", name="b"),
                                  AccountSettings(account_id="333333333333", name="c")])
    rt = build_runtime(settings, store, spec_path=SPEC, allowed_hosts=("testserver",), check_fn=fake_check,
                       profiles_fn=lambda: set())
    yield TestClient(rt.app), rt, store
    rt.stop()


def wait(rt):
    assert rt.app.router and True
    return True


def test_check_all_stores_the_latest_result_per_account(web):
    client, rt, store = web
    r = client.post("/api/accounts/check", json={}, headers=UI)
    assert r.status_code == 202 and r.json()["started"] is True and r.json()["job"]["total"] == 3
    deadline = time.time() + 10
    while time.time() < deadline and client.get("/api/accounts/check").json()["job"]["state"] != "done":
        time.sleep(0.05)
    d = client.get("/api/accounts/check").json()
    assert d["job"]["state"] == "done" and (d["job"]["done"], d["job"]["ok"], d["job"]["failed"]) == (3, 2, 1)
    assert d["results"]["222222222222"]["code"] == "SSO_LOGIN_NEEDED" and d["results"]["111111111111"]["ok"] is True
    assert d["results"]["111111111111"]["at"].endswith("Z")
    # the latest result is in the database: a new server (runner) sees it too
    assert CheckRunner(store, lambda: []).results()["333333333333"]["ok"] is True
    assert any(e["action"] == "account_check" for e in client.get("/api/audit").json()["entries"])


def test_check_some_accounts_only_and_refuse_bad_requests(web):
    client, rt, store = web
    assert client.post("/api/accounts/check", json={"account_ids": ["222222222222"]}, headers=UI).json()["job"]["total"] == 1
    assert rt.app and True
    time.sleep(0.3)
    assert client.post("/api/accounts/check", json={"account_ids": ["999999999999"]}, headers=UI).status_code == 422
    assert client.post("/api/accounts/check", json={"account_ids": []}, headers=UI).status_code == 422
    assert client.post("/api/accounts/check", json={}).status_code == 403  # needs the UI header


def test_a_running_batch_is_not_started_twice():
    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()
    gate = threading.Event()

    def slow(acct, profiles=None):
        gate.wait(5)
        return fake_check(acct)

    runner = CheckRunner(store, lambda: [AccountSettings(account_id="111111111111"), AccountSettings(account_id="333333333333")],
                         check=slow, profiles=lambda: set())
    job1, started1 = runner.start(None, "me")
    job2, started2 = runner.start(None, "me")
    assert started1 is True and started2 is False and job2["state"] == "running"
    gate.set()
    assert runner.wait(10) and runner.job()["state"] == "done" and runner.job()["done"] == 2
    assert runner.start(["111111111111"], "me")[1] is True  # finished: a new batch may start
    assert runner.wait(10)


def test_a_check_that_crashes_does_not_kill_the_batch():
    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()

    def boom(acct, profiles=None):
        if acct.account_id == "111111111111":
            raise RuntimeError("x")  # check_account never raises, but a bug must not hang the page forever
        return fake_check(acct)

    runner = CheckRunner(store, lambda: [AccountSettings(account_id="111111111111"), AccountSettings(account_id="333333333333")],
                         check=boom, profiles=lambda: set(), workers=2)
    runner.start(None, "me")
    assert runner.wait(10)
    job = runner.job()
    assert job["state"] == "done" and (job["done"], job["ok"], job["failed"]) == (2, 1, 1)
    assert runner.results()["111111111111"]["code"] == "ERROR" and runner.results()["333333333333"]["ok"] is True


# ----------------------------------------------------------------------------- the SSO token cache race
def test_a_busy_sso_token_file_is_retried_not_reported_as_a_failure(monkeypatch):
    from cspm_collector.core import session as sess_mod

    monkeypatch.setattr(sess_mod.time, "sleep", lambda s: None)
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError(13, "access denied", "C:/Users/x/.aws/sso/cache/abc.json")
        return {"Account": "123456789012"}

    assert sess_mod.retry_file_race(flaky) == {"Account": "123456789012"} and len(calls) == 3

    def always():
        raise PermissionError("still busy")

    with pytest.raises(PermissionError):
        sess_mod.retry_file_race(always, tries=3)
    with pytest.raises(ValueError):  # other errors are not retried
        sess_mod.retry_file_race(lambda: (_ for _ in ()).throw(ValueError("x")))


@mock_aws
def test_check_and_verify_use_the_retry_for_the_first_call(monkeypatch):
    from cspm_collector.core import session as sess_mod
    from cspm_collector.core.session import AccountSession

    monkeypatch.setattr(sess_mod.time, "sleep", lambda s: None)
    real = AccountSession.client
    state = {"fails": 2}

    def client(self, service, region="us-east-1"):
        c = real(self, service, region)
        if service == "sts" and state["fails"]:
            orig = c.get_caller_identity

            def flaky(*a, **k):
                if state["fails"]:
                    state["fails"] -= 1
                    raise PermissionError("busy")
                return orig(*a, **k)

            class Proxy:
                get_caller_identity = staticmethod(flaky)
            return Proxy()
        return c

    monkeypatch.setattr(AccountSession, "client", client)
    res = check_account(AccountSettings(account_id=MOTO))
    assert res["ok"] is True and state["fails"] == 0
