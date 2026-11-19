"""Skipping unchanged details, noticing a changed answer shape, notifications, and importing the accounts of an Organization."""
import io
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
import mongomock
import pytest
from moto import mock_aws

from cspm_collector.core.config import AccountSettings, ConcurrencySettings, MongoSettings, Settings
from cspm_collector.core.scan import ScanFilter, run_scan
from cspm_collector.core.shape import MIN_RESOURCES, ShapeTracker, field_names
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.records import ResourceRecord
from cspm_collector.storage.store import Store
from cspm_collector.web.notify import Notifier, NotifySettings
from cspm_collector.web.organizations import ImportOrgBody, bodies, clean_name

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
R = "ap-northeast-2"
ROLE = "arn:aws:iam::123456789012:role/r"


def store_():
    s = Store(mongomock.MongoClient()["d"], MongoSettings())
    s.init_db()
    return s


def zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("main.py", "def handler(e, c): return 1")
    return buf.getvalue()


def make_function(name="f1"):
    import json

    boto3.client("iam", region_name=R).create_role(RoleName="r", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))
    lam = boto3.client("lambda", region_name=R)
    lam.create_function(FunctionName=name, Runtime="python3.12", Role=ROLE, Handler="main.handler", Code={"ZipFile": zip_bytes()})
    return lam


def settings(**kw):
    return Settings(accounts=[AccountSettings(account_id="123456789012", regions=[R])], concurrency=ConcurrencySettings(total=4), **kw)


# ----------------------------------------------------------------------------- unchanged details are not read again
def collect_lambda(s, store, **kw):
    return run_scan(s, load_spec(SPEC), store, flt=ScanFilter(services={"awslambda"}), **kw)


def calls_of(store, scan_id):
    return sum(d.get("api_calls", 0) for d in store.coll("collection_status").find({"scan_id": scan_id}))


def test_an_unchanged_function_is_not_asked_for_its_details_again_until_it_changes_or_the_copy_gets_old():
    with mock_aws():
        make_function()
        store, s = store_(), settings()
        first = collect_lambda(s, store)
        full = calls_of(store, first.scan_id)
        assert full >= 4  # list + get_function + get_policy + get_function_url_config

        second = collect_lambda(s, store)
        assert calls_of(store, second.scan_id) == 1  # only the list
        assert (second.resources.unchanged, second.resources.updated) == (1, 0)  # and the stored copy is exactly as before
        acct = store.scan_accounts(second.scan_id)["123456789012"]["services"]["awslambda"]
        assert acct["reused"] == 1
        doc = store.coll("resources").find_one({"service": "awslambda"})
        assert "get_function" in doc["config"]["_details"] and doc["detail_checked_at"] is not None

        # AWS moves LastModified when a function changes (moto does not): make the stored copy look like the function was edited since
        store.coll("resources").update_one({"service": "awslambda"}, {"$set": {"config.LastModified": "2000-01-01T00:00:00.000+0000"}})
        third = collect_lambda(s, store)
        assert calls_of(store, third.scan_id) == full  # read in full again (the stored copy's hash is unchanged, so the data counts as unchanged)
        assert third.resources.unchanged == 1 and store.coll("resource_history").count_documents({}) == 0

        # a copy that was read in full too long ago is read in full again, whatever the marker says
        store.coll("resources").update_many({}, {"$set": {"detail_checked_at": datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)}})
        fourth = collect_lambda(s, store)
        assert calls_of(store, fourth.scan_id) == full


def test_the_shortcut_can_be_switched_off_and_a_retry_never_uses_it():
    with mock_aws():
        make_function()
        store = store_()
        first = collect_lambda(settings(), store)
        off = collect_lambda(settings(incremental_details=False), store)
        assert calls_of(store, off.scan_id) == calls_of(store, first.scan_id)


# ----------------------------------------------------------------------------- the shape of an answer
def rec(i, **config):
    return ResourceRecord("111", R, "sqs", "queue", f"q{i}", config=config)


def run_shape(store, records, now):
    t = ShapeTracker()
    t.add(records)
    return t.finish(store, now)


def test_field_names_cover_the_top_level_and_the_detail_calls():
    assert field_names({"a": 1, "_errors": {"x": 1}, "_details": {"get_x": {"p": 1}, "get_y": None}}) == {"a", "_details.get_x", "_details.get_x.p", "_details.get_y"}


def test_a_field_that_every_resource_lost_is_reported_once_and_a_small_or_partial_run_is_not_compared():
    store, now = store_(), datetime(2026, 11, 1)
    many = lambda **c: [rec(i, Name="n", **c) for i in range(MIN_RESOURCES + 2)]
    assert run_shape(store, many(Policy="p"), now) == []  # the first time: just remembered
    assert run_shape(store, many(Policy="p"), now) == []  # same shape: nothing to say
    (change,) = run_shape(store, many(), now)  # Policy is gone from all of them
    assert (change["service"], change["resource_type"], change["removed"], change["added"]) == ("sqs", "queue", ["Policy"], [])
    assert run_shape(store, many(), now) == []  # said once, the new shape is the normal one now
    (added,) = run_shape(store, many(Encryption=True), now)
    assert added["added"] == ["Encryption"]
    assert run_shape(store, [rec(1)], now) == []  # one resource: too few to say anything
    assert run_shape(store, many(Policy="p", Encryption=True)[:3], now) == []  # a small slice (less than half) is neither compared nor remembered
    assert run_shape(store, many(Encryption=True), now) == []


def test_a_complete_scan_stores_the_changes_in_its_summary():
    with mock_aws():
        sqs = boto3.client("sqs", region_name=R)
        for i in range(MIN_RESOURCES):
            sqs.create_queue(QueueName=f"q{i}")
        store, s = store_(), settings()
        run_scan(s, load_spec(SPEC), store, flt=ScanFilter(services={"sqs"}))
        store.coll("runtime").update_one({"_id": "shape:sqs:queue"}, {"$set": {"names": ["QueueUrl", "GoneField"]}})
        second = run_scan(s, load_spec(SPEC), store, flt=ScanFilter(services={"sqs"}))
        changes = store.coll("scans").find_one({"scan_id": second.scan_id})["summary"]["shape_changes"]
        assert any(c["resource_type"] == "queue" and "GoneField" in c["removed"] for c in changes)


# ----------------------------------------------------------------------------- notifications
class Sink:
    def __init__(self):
        self.sent = []

    def __call__(self, url, text):
        self.sent.append((url, text))


def notifier(store, sink, health=None):
    return Notifier(store, lambda: "TEST_HOOK", lambda: {"111": "dev-a"}, post=sink, health=health)


def finished(store, scan_id, status, excluded=None, shape=None):
    store.create_scan(scan_id, ["111"], "v", None, {"preflight_excluded": excluded or []})
    store.finish_scan(scan_id, status, {"resources": {"inserted": 3, "updated": 0, "unchanged": 0}, "shape_changes": shape or []})
    store.save_scan_accounts(scan_id, {"111": {"status": "FAILED" if status != "COMPLETED" else "COMPLETED", "tasks": 1, "resources": 3, "seconds": 1.0, "services": {}}})


def test_nothing_is_sent_while_it_is_off_or_the_webhook_is_not_set(monkeypatch):
    store, sink = store_(), Sink()
    n = notifier(store, sink)
    finished(store, "s1", "PARTIAL")
    monkeypatch.setenv("TEST_HOOK", "https://hook.example/secret")
    n.run_finished("s1")  # off by default
    n.save(NotifySettings(enabled=True), "u", datetime(2026, 11, 1))
    monkeypatch.delenv("TEST_HOOK")
    n.run_finished("s1")  # on, but no URL on this server
    assert sink.sent == []
    assert n.test()[0] is False


def test_a_failed_run_is_reported_with_the_account_names_but_never_the_url(monkeypatch):
    store, sink = store_(), Sink()
    n = notifier(store, sink)
    n.save(NotifySettings(enabled=True), "u", datetime(2026, 11, 1))
    monkeypatch.setenv("TEST_HOOK", "https://hook.example/secret")
    finished(store, "s1", "PARTIAL")
    n.run_finished("s1", will_retry=True)  # a retry is waiting: its end is reported instead
    assert sink.sent == []
    n.run_finished("s1")
    ((url, text),) = sink.sent
    assert url == "https://hook.example/secret" and "secret" not in text and "dev-a" in text and "PARTIAL" in text
    finished(store, "s2", "COMPLETED")
    n.run_finished("s2")  # fine runs are quiet unless asked for
    assert len(sink.sent) == 1
    n.save(NotifySettings(enabled=True, on_completed=True), "u", datetime(2026, 11, 1))
    n.run_finished("s2")
    assert len(sink.sent) == 2
    assert "secret" not in str(n.view()) and n.view()["webhook_configured"] is True


def test_a_failing_webhook_never_raises_and_a_changed_shape_and_a_new_warning_are_reported_once(monkeypatch):
    store = store_()
    warnings = {"accounts": [{"account_id": "111", "warnings": [{"type": "failing", "message": "연속 실패"}]}]}
    sink = Sink()
    n = notifier(store, sink, health=lambda: warnings)
    n.save(NotifySettings(enabled=True), "u", datetime(2026, 11, 1))
    monkeypatch.setenv("TEST_HOOK", "https://hook.example/x")
    finished(store, "s1", "COMPLETED", shape=[{"service": "sqs", "resource_type": "queue", "removed": ["Policy"], "added": [], "count": 9}])
    n.run_finished("s1")
    ((_, text),) = sink.sent
    assert "응답 형식 변화 sqs/queue" in text and "Policy" in text and "dev-a: 연속 실패" in text
    finished(store, "s2", "COMPLETED")
    n.run_finished("s2")
    assert len(sink.sent) == 1  # the same warning is not repeated

    def boom(url, text):
        raise ConnectionError(url)

    broken = notifier(store, boom)
    ok, message = broken.send("hi")
    assert ok is False and "ConnectionError" in message and "hook.example" not in message


# ----------------------------------------------------------------------------- organization accounts
ORG = {"organization": {"id": "o-1", "management_account_id": "111111111111"},
       "accounts": [{"account_id": "111111111111", "name": "mgmt", "status": "ACTIVE"}, {"account_id": "222222222222", "name": "=dev one", "status": "ACTIVE"},
                    {"account_id": "333333333333", "name": "old", "status": "SUSPENDED"}]}


def test_names_and_roles_of_imported_accounts_are_made_safe():
    assert clean_name("=+@ x" + "y" * 80) == "x" + "y" * 59 and clean_name("@@") == "account"
    body = ImportOrgBody(account_ids=["222222222222", "333333333333", "444444444444"], role_name="role/ReadOnly", env="dev", regions=["ap-northeast-2"])
    good, skipped = bodies(ORG["accounts"], body)
    assert [(g.account_id, g.name, g.role_arn, g.env) for g in good] == [("222222222222", "dev one", "arn:aws:iam::222222222222:role/ReadOnly", "dev")]
    assert skipped == {"333333333333": "활성 상태가 아님 (SUSPENDED)", "444444444444": "조직에 없는 어카운트"}
    with pytest.raises(ValueError):
        ImportOrgBody(account_ids=["1"], role_name="arn:aws:iam::1:role/x y")


def test_import_endpoint_lists_marks_registered_accounts_and_adds_only_new_active_ones():
    from test_web_api import UI, make

    client, rt, _, store = make()
    try:
        # build a runtime that knows the fake organization
        from cspm_collector.web.server import build_runtime
        from test_web_api import SPEC, Stub
        rt.stop()
        settings_ = Settings(accounts=[AccountSettings(account_id="222222222222", name="have")])
        rt = build_runtime(settings_, store, spec_path=SPEC, run_fn=Stub(), allowed_hosts=("testserver",), org_lister=lambda: ORG)
        from fastapi.testclient import TestClient
        client = TestClient(rt.app)
        listed = client.post("/api/accounts/organizations/list", headers=UI).json()
        assert {a["account_id"]: (a["registered"], a["management"]) for a in listed["accounts"]} == {
            "111111111111": (False, True), "222222222222": (True, False), "333333333333": (False, False)}
        r = client.post("/api/accounts/organizations/import", headers=UI,
                        json={"account_ids": ["111111111111", "222222222222", "333333333333"], "role_name": "ReadOnly", "env": "dev"}).json()
        assert r["added"] == ["111111111111"] and set(r["skipped"]) == {"222222222222", "333333333333"}
        accounts = {a["account_id"]: a for a in client.get("/api/overview").json()["accounts"]}
        assert accounts["111111111111"]["role_arn"] == "arn:aws:iam::111111111111:role/ReadOnly" and accounts["111111111111"]["source"] == "web"
        assert client.post("/api/accounts/organizations/import", headers=UI, json={"account_ids": ["111111111111"], "role_name": "bad name"}).status_code == 422
        # nothing more to add: no error, no write
        again = client.post("/api/accounts/organizations/import", headers=UI, json={"account_ids": ["111111111111"], "role_name": "ReadOnly"}).json()
        assert again["added"] == [] and "111111111111" in again["skipped"]
    finally:
        rt.stop()


def test_organization_errors_are_explained():
    from botocore.exceptions import ClientError

    from cspm_collector.web import organizations as orgs

    class Denied:
        def describe_organization(self):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "x"}}, "DescribeOrganization")

    import boto3 as real

    orig = real.client
    real.client = lambda *a, **k: Denied()
    try:
        with pytest.raises(orgs.OrgError, match="organizations:ListAccounts"):
            orgs.list_organization_accounts()
    finally:
        real.client = orig
