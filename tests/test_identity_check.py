"""A missing role_arn must never make the collector store another account's resources under the configured id."""
from pathlib import Path

import boto3
import mongomock
import pytest
from moto import mock_aws

from cspm_collector.core.config import AccountSettings, ConcurrencySettings, MongoSettings, Settings
from cspm_collector.core.scan import ScanFilter, run_scan
from cspm_collector.core.session import AccountMismatch, AccountSession
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.store import Store

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
R = "ap-northeast-2"
MOTO = "123456789012"  # the account moto's credentials belong to


@mock_aws
def test_matching_account_passes_and_a_foreign_one_is_refused_with_a_hint():
    assert AccountSession(AccountSettings(account_id=MOTO)).verify_identity() == MOTO
    with pytest.raises(AccountMismatch) as e:
        AccountSession(AccountSettings(account_id="999999999999")).verify_identity()
    assert MOTO in str(e.value) and "999999999999" in str(e.value) and "role_arn" in str(e.value)


@mock_aws
def test_scan_fails_the_account_instead_of_storing_the_ambient_accounts_data():
    boto3.client("sqs", region_name=R).create_queue(QueueName="q1")  # belongs to the moto (ambient) account
    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()
    settings = Settings(accounts=[AccountSettings(account_id="999999999999", name="someone-else", regions=[R]),
                                  AccountSettings(account_id=MOTO, name="ambient", regions=[R])],
                        concurrency=ConcurrencySettings(total=2, per_account=2, per_service=2))
    run_scan(settings, load_spec(SPEC), store, flt=ScanFilter(services={"sqs"}))
    stored = {d["account_id"] for d in store.coll("resources").find({})}
    assert stored == {MOTO}  # nothing was stored under the account that the credentials do not belong to
    bad = list(store.coll("collection_status").find({"account_id": "999999999999"}))
    assert [(d["status"], d["error_code"]) for d in bad] == [("ERROR", "AccountMismatch")]
    assert "999999999999" in bad[0]["error"]


@mock_aws
def test_the_check_can_be_switched_off():
    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()
    settings = Settings(accounts=[AccountSettings(account_id="999999999999", regions=[R])], verify_account_identity=False)
    run_scan(settings, load_spec(SPEC), store, flt=ScanFilter(services={"sqs"}))
    assert not list(store.coll("collection_status").find({"error_code": "AccountMismatch"}))


def test_account_session_uses_its_aws_profile(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.write_text("[profile acct-a]\naws_access_key_id = AKIAAAAAAAAAAAAAAAAA\naws_secret_access_key = secretsecretsecretsecret\nregion = ap-northeast-2\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    s = AccountSession(AccountSettings(account_id="111122223333", profile="acct-a"))
    assert s._base.profile_name == "acct-a"
    assert s._base.get_credentials().access_key == "AKIAAAAAAAAAAAAAAAAA"
    assert AccountSession(AccountSettings(account_id="111122223333"))._base.profile_name == "default"


@mock_aws
def test_a_profile_that_points_at_another_account_is_refused_and_names_the_profile():
    with pytest.raises(AccountMismatch) as e:
        AccountSession(AccountSettings(account_id="999999999999", profile=None)).verify_identity()
    assert "AWS 프로필이나 role_arn" in str(e.value)


@mock_aws
def test_accounts_are_opened_side_by_side_and_keep_their_order():
    import threading
    import time

    spans, lock = [], threading.Lock()

    class Slow(AccountSession):
        def verify_identity(self):
            began = time.perf_counter()
            time.sleep(0.4)  # stands for the network calls of an SSO / STS check
            with lock:
                spans.append((began, time.perf_counter()))
            return self.account.account_id

    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()
    ids = [f"11111111111{n}" for n in range(6)]
    settings = Settings(accounts=[AccountSettings(account_id=i, regions=[R]) for i in ids],
                        concurrency=ConcurrencySettings(total=2, per_account=1, per_service=2))
    s = run_scan(settings, load_spec(SPEC), store, flt=ScanFilter(services={"sqs"}), session_factory=Slow)
    assert len(spans) == 6
    # one after the other, the last would start after the first ended; side by side they all overlap
    assert max(b for b, _ in spans) < min(e for _, e in spans), "accounts were opened one after the other"
    assert store.coll("scans").find_one({"scan_id": s.scan_id})["accounts"] == ids  # order of the settings is kept
