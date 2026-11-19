import json
from pathlib import Path

import boto3
import mongomock
import pytest
import yaml
from moto import mock_aws
from typer.testing import CliRunner

from cspm_collector.cli import main
from cspm_collector.cli.main import app

ROOT = Path(__file__).resolve().parents[1]
SPEC = str(ROOT / "spec" / "collect_spec.yaml")
runner = CliRunner()


@pytest.fixture
def mongo(monkeypatch):
    client = mongomock.MongoClient()
    monkeypatch.setattr(main, "MongoClient", lambda uri: client)
    return client


def config(tmp_path, **extra):
    cfg = {"spec_path": SPEC, "mongo": {"database": "clitest"},
           "accounts": [{"account_id": "123456789012", "regions": ["us-east-1"]}], **extra}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return str(path)


def test_list_spec_filters():
    out = runner.invoke(app, ["list-spec", SPEC, "--services", "kms,sqs"]).output
    assert "[T1] kms (regional, generic" in out and "kms.list_keys" in out and "sqs.list_queues" in out
    assert "ec2" not in out
    assert "[T3]" not in runner.invoke(app, ["list-spec", SPEC, "--tier", "1"]).output
    only_enabled = runner.invoke(app, ["list-spec", SPEC, "--enabled-only"]).output
    assert "resourcegroupstaggingapi" not in only_enabled


def test_validate_spec_exit_codes(tmp_path):
    ok = runner.invoke(app, ["validate-spec", SPEC])
    assert ok.exit_code == 0 and "0 errors" in ok.output

    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"spec_version": "t", "services": [
        {"service": "s3", "client": "s3", "apis": [{"api": "delete_bucket"}]}]}), encoding="utf-8")
    res = runner.invoke(app, ["validate-spec", str(bad)])
    assert res.exit_code == 1 and "mutating API" in res.output and "ERROR" in res.output


def test_iam_policy_command_writes_files(tmp_path):
    res = runner.invoke(app, ["iam-policy", SPEC, "--out-dir", str(tmp_path / "pol")])
    assert res.exit_code == 0 and "actions in" in res.output
    docs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((tmp_path / "pol").glob("policy-*.json"))]
    assert len(docs) >= 2 and all(d["Statement"][0]["Effect"] == "Allow" for d in docs)


def test_build_and_assemble_spec_roundtrip(tmp_path):
    svc = tmp_path / "prowler" / "providers" / "aws" / "services" / "ec2"
    svc.mkdir(parents=True)
    (svc / "ec2_service.py").write_text("def f(regional_client):\n    regional_client.describe_security_groups()\n", encoding="utf-8")
    cfg = tmp_path / "prowler" / "config"
    cfg.mkdir(parents=True)
    (cfg / "config.py").write_text('prowler_version = "9.9.9"\n', encoding="utf-8")
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([{"check_id": "ec2_a", "service": "ec2"}]), encoding="utf-8")
    generated, report = tmp_path / "gen.yaml", tmp_path / "report.json"
    res = runner.invoke(app, ["build-spec", "--prowler-root", str(tmp_path), "--rules", str(rules),
                              "--out-yaml", str(generated), "--out-report", str(report)])
    assert res.exit_code == 0 and "1 services, 1 apis" in res.output and "prowler_version=9.9.9" in res.output
    assert json.loads(report.read_text(encoding="utf-8"))["unresolved_apis"] == {}

    overrides = tmp_path / "overrides"
    overrides.mkdir()
    (overrides / "sqs.yaml").write_text(
        "service: sqs\nclient: sqs\napis:\n  - {api: list_queues, result_path: QueueUrls, id_field: Value}\n", encoding="utf-8")
    active = tmp_path / "active.yaml"
    res = runner.invoke(app, ["assemble-spec", "--generated", str(generated), "--overrides", str(overrides),
                              "--out-yaml", str(active)])
    assert res.exit_code == 0 and "2 services (1 enabled: sqs)" in res.output


def test_build_spec_rejects_a_wrong_prowler_root(tmp_path):
    res = runner.invoke(app, ["build-spec", "--prowler-root", str(tmp_path), "--rules", str(tmp_path / "r.json")])
    assert res.exit_code != 0 and "providers" in res.output


def test_ensure_indexes_and_foreign_database_refusal(tmp_path, mongo):
    cfg = config(tmp_path)
    assert runner.invoke(app, ["ensure-indexes", "--config", cfg]).exit_code == 0
    assert "cspm_meta" in mongo["clitest"].list_collection_names()

    mongo["foreign"]["resources"].insert_one({"x": 1})
    cfg2 = tmp_path / "foreign.yaml"
    cfg2.write_text(yaml.safe_dump({"mongo": {"database": "foreign"}}), encoding="utf-8")
    res = runner.invoke(app, ["ensure-indexes", "--config", str(cfg2)])
    assert res.exit_code != 0 and "ForeignCollectionError" in repr(res.exception)


def test_run_status_and_retry(tmp_path, mongo):
    cfg = config(tmp_path)
    with mock_aws():
        boto3.client("sqs", region_name="us-east-1").create_queue(QueueName="q1")
        res = runner.invoke(app, ["run", "--config", cfg, "--services", "sqs"])
        assert res.exit_code == 0, res.output
        assert "COMPLETED" in res.output and "total API calls" in res.output
        scan = mongo["clitest"].scans.find_one({})
        assert mongo["clitest"].resources.count_documents({"service": "sqs"}) == 1

        status = runner.invoke(app, ["status", scan["scan_id"], "--config", cfg])
        assert status.exit_code == 0 and scan["scan_id"] in status.output and "COMPLETED" in status.output

        unknown = runner.invoke(app, ["run", "--config", cfg, "--services", "sqs", "--retry-failed", "nope"])
        assert unknown.exit_code == 2 and "unknown scan" in unknown.output

        nothing = runner.invoke(app, ["run", "--config", cfg, "--services", "sqs", "--retry-failed", scan["scan_id"]])
        assert nothing.exit_code == 0 and "retrying 0 ranges" in nothing.output and "COMPLETED" in nothing.output


def test_run_requires_accounts_and_valid_spec(tmp_path, mongo):
    empty = tmp_path / "empty.yaml"
    empty.write_text(yaml.safe_dump({"mongo": {"database": "x"}}), encoding="utf-8")
    assert runner.invoke(app, ["run", "--config", str(empty)]).exit_code == 2

    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"spec_version": "t", "services": [
        {"service": "s3", "client": "s3", "apis": [{"api": "delete_bucket"}]}]}), encoding="utf-8")
    res = runner.invoke(app, ["run", "--config", config(tmp_path), "--spec", str(bad)])
    assert res.exit_code == 2 and "mutating" in res.output


def test_akamai_check(tmp_path, monkeypatch):
    class Fake:
        def __init__(self, ok):
            self.ok = ok

        def get(self, path, params=None, headers=None):
            if not self.ok:
                raise RuntimeError("bad credentials")
            return {"groups": {"items": [{"groupId": "g"}, {"groupId": "h"}]}}

    cfg = config(tmp_path, akamai=[{"name": "good", "env_prefix": "X"}, {"name": "bad", "env_prefix": "Y"}])
    monkeypatch.setattr(main.EdgeGridClient, "from_settings", staticmethod(lambda acct: Fake(acct.name == "good")))
    res = runner.invoke(app, ["akamai-check", "--config", cfg])
    assert res.exit_code == 1 and "OK   good: 2 groups visible" in res.output and "FAIL bad" in res.output

    no_akamai = tmp_path / "none.yaml"
    no_akamai.write_text("{}", encoding="utf-8")
    assert runner.invoke(app, ["akamai-check", "--config", str(no_akamai)]).exit_code == 2
