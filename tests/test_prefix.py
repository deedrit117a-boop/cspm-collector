import boto3
import mongomock
import pytest
import yaml
from moto import mock_aws
from typer.testing import CliRunner

from cspm_collector.cli import main
from cspm_collector.cli.main import app
from cspm_collector.core.config import AccountSettings, MongoSettings, Settings, load_settings
from cspm_collector.core.scan import ScanFilter, plan_retry, run_scan
from cspm_collector.spec.loader import load_spec
from cspm_collector.storage.records import ResourceRecord
from cspm_collector.storage.store import MANAGED_COLLECTIONS, ForeignCollectionError, Store, rename_collections

from pathlib import Path

SPEC = Path(__file__).resolve().parents[1] / "spec" / "collect_spec.yaml"
OURS = ["scans", "collection_status", "resources", "resource_history", "resource_chunks", "account_settings",
        "akamai_raw", "cspm_meta"]


def rec(i="a"):
    return ResourceRecord("1", "r", "svc", "t", i, config={"k": i})


def test_everything_lands_in_prefixed_collections():
    db = mongomock.MongoClient()["d"]
    store = Store(db, MongoSettings(collection_prefix="000_"))
    store.init_db()
    store.create_scan("s1", ["1"], "v")
    store.save_resources("s1", [rec()])
    store.save_account_setting("s1", "1", "r", "x", {"a": 1})
    assert set(db.list_collection_names()) >= {"000_scans", "000_resources", "000_account_settings", "000_cspm_meta"}
    assert not ({"scans", "resources", "account_settings", "cspm_meta", "collection_status"} & set(db.list_collection_names()))
    assert db["000_resources"].count_documents({}) == 1 and store.coll("resources").count_documents({}) == 1
    names = {n: [i["name"] for i in db[n].list_indexes()] for n in ("000_resources", "000_akamai_raw")}
    assert len(names["000_resources"]) == 5 and len(names["000_akamai_raw"]) == 8  # indexes follow the prefix too


def test_foreign_collection_guard_uses_the_prefixed_names():
    db = mongomock.MongoClient()["d"]
    db["resources"].insert_one({"x": 1})  # a foreign collection with the UNprefixed name is no conflict
    Store(db, MongoSettings(collection_prefix="000_")).init_db()
    assert db["resources"].count_documents({}) == 1  # untouched

    db2 = mongomock.MongoClient()["d2"]
    db2["000_resources"].insert_one({"x": 1})
    with pytest.raises(ForeignCollectionError, match="000_resources"):
        Store(db2, MongoSettings(collection_prefix="000_")).init_db()


def test_scan_retry_and_status_work_with_a_prefix(tmp_path, monkeypatch):
    client = mongomock.MongoClient()
    with mock_aws():
        boto3.client("sqs", region_name="us-east-1").create_queue(QueueName="q1")
        settings = Settings(accounts=[AccountSettings(account_id="123456789012", regions=["us-east-1"])],
                            mongo=MongoSettings(collection_prefix="000_"))
        store = Store(client["cspm"], settings.mongo)
        s = run_scan(settings, load_spec(SPEC), store, flt=ScanFilter(services={"sqs"}))
        assert s.status == "COMPLETED"
        assert client["cspm"]["000_resources"].count_documents({"service": "sqs"}) == 1
        assert client["cspm"]["000_collection_status"].count_documents({"scan_id": s.scan_id}) > 0
        assert "resources" not in client["cspm"].list_collection_names()
        assert plan_retry(store, s.scan_id).tasks == frozenset()

        cfg = tmp_path / "c.yaml"
        cfg.write_text(yaml.safe_dump({"mongo": {"database": "cspm", "collection_prefix": "000_"}}), encoding="utf-8")
        monkeypatch.setattr(main, "MongoClient", lambda uri: client)
        out = CliRunner().invoke(app, ["status", s.scan_id, "--config", str(cfg)])
        assert out.exit_code == 0 and s.scan_id in out.output


def test_env_override(monkeypatch):
    monkeypatch.setenv("MONGO_COLLECTION_PREFIX", "000_")
    assert load_settings().mongo.collection_prefix == "000_"
    monkeypatch.setenv("MONGO_COLLECTION_PREFIX", "")
    assert load_settings().mongo.collection_prefix == ""  # an explicit empty value turns it off again


# ------------------------------------------------------------------------------ renaming existing data
def populated():
    db = mongomock.MongoClient()["d"]
    plain = Store(db, MongoSettings())
    plain.init_db()
    plain.create_scan("s1", ["1"], "v")
    plain.save_resources("s1", [rec("a"), rec("b")])
    return db, plain


def test_rename_keeps_data_and_indexes_and_change_detection():
    db, _ = populated()
    pairs = rename_collections(db, "", "000_")
    # only collections that exist are renamed: those the collector has created so far (a collection appears when it is
    # first written to or indexed; "runtime" and "audit" belong to the control page)
    created = {old for old, _ in pairs}
    assert dict(pairs)["resources"] == "000_resources" and {"scans", "resources", "cspm_meta"} <= created
    assert created <= set(MANAGED_COLLECTIONS) | {"cspm_meta"}
    assert not set(OURS) & set(db.list_collection_names())
    assert db["000_resources"].count_documents({}) == 2 and db["000_scans"].count_documents({}) == 1
    assert len(list(db["000_resources"].list_indexes())) == 5

    prefixed = Store(db, MongoSettings(collection_prefix="000_"))
    prefixed.init_db()  # recognises its own (renamed) marker: no ForeignCollectionError
    stats = prefixed.save_resources("s2", [rec("a"), rec("b")])
    assert (stats.inserted, stats.updated, stats.unchanged) == (0, 0, 2)  # same documents, nothing re-inserted


def test_rename_refuses_unsafe_situations():
    db = mongomock.MongoClient()["d"]
    db["resources"].insert_one({"x": 1})  # somebody else's collection, no cspm_meta marker
    with pytest.raises(ValueError, match="not created by this collector"):
        rename_collections(db, "", "000_")
    assert "resources" in db.list_collection_names()

    db, _ = populated()
    db["000_resources"].insert_one({"x": 1})  # target already taken
    with pytest.raises(ValueError, match="already exist"):
        rename_collections(db, "", "000_")
    assert "resources" in db.list_collection_names()  # nothing was renamed

    with pytest.raises(ValueError, match="same"):
        rename_collections(db, "", "")


def test_rename_command(tmp_path, monkeypatch):
    db, _ = populated()
    client = db.client
    monkeypatch.setattr(main, "MongoClient", lambda uri: client)
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"mongo": {"database": "d"}}), encoding="utf-8")
    res = CliRunner().invoke(app, ["rename-collections", "--to-prefix", "000_", "--config", str(cfg)])
    assert res.exit_code == 0 and "resources -> 000_resources" in res.output and "collection_prefix" in res.output
    again = CliRunner().invoke(app, ["rename-collections", "--to-prefix", "000_", "--config", str(cfg)])
    assert again.exit_code == 2  # the old names are gone: refuses instead of guessing
