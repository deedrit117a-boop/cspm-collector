import json

from cspm_collector.spec.builder import build_spec, read_prowler_version, scan_service_file
from cspm_collector.spec.loader import validate_spec

SERVICE_SRC = '''
class EC2(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
    def _sgs(self, regional_client):
        regional_client.describe_security_groups()
        regional_client.get_paginator("describe_instances")
        regional_client.describe_instance_attribute(InstanceId="i", Attribute="userData")
        regional_client.terminate_instances()
        d = {}
        d.get("x")
'''


def _tree(tmp_path, src=SERVICE_SRC):
    d = tmp_path / "services" / "ec2"
    d.mkdir(parents=True)
    (d / "ec2_service.py").write_text(src, encoding="utf-8")
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([{"check_id": "ec2_a", "service": "ec2"}]), encoding="utf-8")
    return tmp_path / "services", rules


def test_scan_ignores_mutating_and_dict_get(tmp_path):
    services, _ = _tree(tmp_path)
    scan = scan_service_file(services / "ec2" / "ec2_service.py")
    assert scan.calls == {"describe_security_groups", "describe_instance_attribute"}
    assert scan.paginators == {"describe_instances"}


def test_global_flag(tmp_path):
    src = "class X:\n    def __init__(self, p):\n        super().__init__('X', p, global_service=True)\n"
    services, _ = _tree(tmp_path, src)
    assert scan_service_file(services / "ec2" / "ec2_service.py").global_service


def test_build_spec(tmp_path):
    services, rules = _tree(tmp_path)
    spec, report = build_spec(services, rules, "1.0")
    svc = spec.services[0]
    assert (svc.service, svc.client, svc.scope, svc.tier, svc.rule_count) == ("ec2", "ec2", "regional", 1, 1)
    apis = {a.api: a for a in svc.apis}
    assert apis["describe_instances"].paginate and apis["describe_instances"].result_path == "Reservations"
    assert apis["describe_instance_attribute"].needs_review  # InstanceId has no parent in the generated set
    assert "terminate_instances" not in apis
    # the unresolved per-resource call is exactly what the validator must flag for a human to fix
    issues = validate_spec(spec)
    assert [(i.where, "missing required parameters" in i.message) for i in issues] == [
        ("ec2.describe_instance_attribute", True)]
    assert spec.source_hash and spec.prowler_version == "1.0"


def test_dependency_resolved_when_parent_lists_the_param(tmp_path):
    src = "def f(c):\n    c.list_buckets()\n    c.get_bucket_policy(Bucket='b')\n"
    d = tmp_path / "services" / "s3"
    d.mkdir(parents=True)
    (d / "s3_service.py").write_text(src.replace("c.", "client."), encoding="utf-8")
    rules = tmp_path / "r.json"
    rules.write_text("[]", encoding="utf-8")
    # list_buckets items expose "Name", not "Bucket" -> stays unresolved, needs review
    spec, _ = build_spec(tmp_path / "services", rules)
    apis = {a.api: a for a in spec.services[0].apis}
    assert apis["get_bucket_policy"].needs_review and apis["get_bucket_policy"].depends_on is None


def test_read_prowler_version(tmp_path):
    cfg = tmp_path / "prowler" / "config"
    cfg.mkdir(parents=True)
    (cfg / "config.py").write_text('prowler_version = "9.9.9"\n', encoding="utf-8")
    assert read_prowler_version(tmp_path) == "9.9.9"
