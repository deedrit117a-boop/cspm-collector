from datetime import datetime, timedelta, timezone

import mongomock
import pytest

from cspm_collector.core.config import MongoSettings
from cspm_collector.core.errors import Status
from cspm_collector.storage.records import ResourceRecord, StatusRecord, SweepScope, resource_key
from cspm_collector.storage.store import ForeignCollectionError, Store

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def store():
    s = Store(mongomock.MongoClient()["cspm"], MongoSettings(batch_size=2))
    s.init_db()
    return s


def sg(i="sg-1", **config):
    return ResourceRecord("111", "ap-northeast-2", "ec2", "security_group", i,
                          config={"GroupId": i, "Rules": [1, 2], **config}, arn=f"arn:{i}",
                          tags=[{"Key": "env", "Value": "prod"}])


def doc(store, rec):
    return store.db.resources.find_one({"_id": rec.key})


def test_first_save_inserts_with_first_seen(store):
    st = store.save_resources("s1", [sg("a"), sg("b"), sg("c")], now=T0)
    assert (st.inserted, st.updated, st.unchanged, st.history) == (3, 0, 0, 0)  # 3 records, batch size 2
    d = doc(store, sg("a"))
    assert d["_id"] == resource_key("111", "ap-northeast-2", "ec2", "security_group", "a")
    assert d["first_seen"] == d["last_seen"] == T0.replace(tzinfo=None) and d["scan_id"] == "s1"
    assert d["tags"] == [{"key": "env", "value": "prod"}] and d["config_chunks"] == 0
    assert store.db.resource_history.count_documents({}) == 0


def test_unchanged_only_touches_last_seen_and_scan_id(store):
    store.save_resources("s1", [sg()], now=T0)
    before = doc(store, sg())
    st = store.save_resources("s2", [sg()], now=T0 + timedelta(days=1))
    after = doc(store, sg())
    assert (st.unchanged, st.updated, st.history) == (1, 0, 0)
    assert after["scan_id"] == "s2" and after["last_seen"] > before["last_seen"]
    assert after["config_changed_at"] == before["config_changed_at"] and after["first_seen"] == before["first_seen"]
    assert store.db.resource_history.count_documents({}) == 0


def test_change_updates_config_and_archives_previous_version(store):
    store.save_resources("s1", [sg(Port=22)], now=T0)
    old_hash = doc(store, sg())["config_hash"]
    st = store.save_resources("s2", [sg(Port=3389)], now=T0 + timedelta(days=1))
    assert (st.updated, st.history) == (1, 1)
    d = doc(store, sg())
    assert d["config"]["Port"] == 3389 and d["config_hash"] != old_hash and d["first_seen"] == T0.replace(tzinfo=None)
    h = store.db.resource_history.find_one({"resource_key": d["_id"]})
    assert h["config"]["Port"] == 22 and h["config_hash"] == old_hash
    assert h["version_scan_id"] == "s1" and h["changed_in_scan"] == "s2"


def test_tag_change_counts_as_change(store):
    store.save_resources("s1", [sg()], now=T0)
    tagged = sg()
    tagged.tags = [{"Key": "env", "Value": "dev"}]
    assert store.save_resources("s2", [tagged], now=T0).updated == 1


def test_key_order_does_not_trigger_change(store):
    a = ResourceRecord("1", "r", "s", "t", "id", config={"x": 1, "y": 2})
    b = ResourceRecord("1", "r", "s", "t", "id", config={"y": 2, "x": 1})
    store.save_resources("s1", [a], now=T0)
    assert store.save_resources("s2", [b], now=T0).unchanged == 1


def test_dotted_keys_are_escaped_and_restored(store):
    rec = ResourceRecord("1", "r", "iam", "policy", "p", config={"Condition": {"aws:SourceArn": "x", "a.b": 1}})
    store.save_resources("s1", [rec], now=T0)
    d = doc(store, rec)
    assert d["key_escaped"] and "a.b" not in d["config"]["Condition"]
    assert store.get_config(d) == rec.config


def test_sweep_soft_deletes_only_unseen_in_swept_scope(store):
    store.save_resources("s1", [sg("a"), sg("b")], now=T0)
    other_scope = ResourceRecord("111", "us-east-1", "ec2", "security_group", "z", config={"k": 1})
    store.save_resources("s1", [other_scope], now=T0)
    store.save_resources("s2", [sg("a")], now=T0 + timedelta(days=1))  # b vanished

    n = store.sweep("s2", [SweepScope("111", "ap-northeast-2", "ec2", None)], now=T0 + timedelta(days=1))
    assert n == 1
    assert doc(store, sg("b"))["deleted_at"] is not None
    assert doc(store, sg("a")).get("deleted_at") is None
    assert doc(store, other_scope).get("deleted_at") is None  # scope was not swept (e.g. collection failed)


def test_sweep_respects_resource_type_filter(store):
    vol = ResourceRecord("111", "r", "ec2", "volume", "v", config={"k": 1})
    inst = ResourceRecord("111", "r", "ec2", "instance", "i", config={"k": 1})
    store.save_resources("s1", [vol, inst], now=T0)
    store.sweep("s2", [SweepScope("111", "r", "ec2", frozenset({"instance"}))], now=T0)
    assert doc(store, inst)["deleted_at"] is not None and doc(store, vol).get("deleted_at") is None


def test_reappearing_resource_is_undeleted(store):
    store.save_resources("s1", [sg()], now=T0)
    store.sweep("s2", [SweepScope("111", "ap-northeast-2", "ec2", None)], now=T0)
    assert doc(store, sg())["deleted_at"] is not None
    store.save_resources("s3", [sg()], now=T0)
    assert doc(store, sg()).get("deleted_at") is None


def test_oversized_config_is_chunked_and_reassembled():
    s = Store(mongomock.MongoClient()["c"], MongoSettings(max_doc_bytes=2000, chunk_bytes=4000))
    s.init_db()
    big = ResourceRecord("1", "global", "route53", "zone", "z", config={"records": [f"r{i}.example.com" for i in range(400)]})
    st = s.save_resources("s1", [big], now=T0)
    d = s.db.resources.find_one({"_id": big.key})
    assert st.chunked == 1 and d["config"] is None and d["config_chunks"] > 1
    assert s.db.resource_chunks.count_documents({"resource_id": big.key}) == d["config_chunks"]
    assert s.get_config(d) == big.config

    small = ResourceRecord("1", "global", "route53", "zone", "z", config={"records": ["only"]})
    s.save_resources("s2", [small], now=T0)
    d = s.db.resources.find_one({"_id": big.key})
    assert d["config_chunks"] == 0 and s.get_config(d) == small.config
    assert s.db.resource_chunks.count_documents({}) == 0
    assert s.db.resource_history.find_one({})["config_truncated"] is True


def test_status_and_settings_and_scans(store):
    store.create_scan("s1", ["111"], "spec-1", "5.46.0", {"tier": 1})
    store.record_status("s1", [
        StatusRecord("111", "r", "s3", "list_buckets", Status.SUCCESS, "bucket", resource_count=0, duration_ms=12.34),
        StatusRecord("111", "r", "iam", "list_users", Status.ACCESS_DENIED, error_code="AccessDenied"),
    ])
    rows = {r["service"]: r for r in store.db.collection_status.find({"scan_id": "s1"})}
    assert rows["s3"]["status"] == "SUCCESS" and rows["s3"]["resource_count"] == 0  # "none found" is recorded
    assert rows["iam"]["status"] == "ACCESS_DENIED" and rows["iam"]["error_code"] == "AccessDenied"

    store.save_account_setting("s1", "111", "r", "ebs_encryption_by_default", {"EbsEncryptionByDefault": True})
    store.save_account_setting("s1", "111", "r", "ebs_encryption_by_default", {"EbsEncryptionByDefault": False})
    assert store.db.account_settings.count_documents({}) == 1  # idempotent per (scan, account, region, setting)

    store.finish_scan("s1", "PARTIAL", {"resources": 0})
    s = store.db.scans.find_one({"scan_id": "s1"})
    assert s["status"] == "PARTIAL" and s["finished_at"] and s["spec_version"] == "spec-1"


def test_refuses_database_with_foreign_collections():
    db = mongomock.MongoClient()["acl"]
    db["resources"].insert_one({"x": 1})  # somebody else's collection with the same name
    with pytest.raises(ForeignCollectionError, match="resources"):
        Store(db).init_db()
    assert db["resources"].count_documents({}) == 1 and "cspm_meta" not in db.list_collection_names()


def test_init_is_idempotent_on_our_own_database(store):
    store.init_db()
    assert store.db.cspm_meta.count_documents({}) == 1
