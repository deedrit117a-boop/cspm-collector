import pytest
from pydantic import ValidationError

from cspm_collector.spec.loader import dump_spec, load_spec, validate_spec
from cspm_collector.spec.schema import ApiSpec, CollectSpec, DependsOn, ServiceSpec


def _spec(*apis, client="s3"):
    return CollectSpec(spec_version="t", services=[ServiceSpec(service="s3", client=client, apis=list(apis))])


def test_roundtrip(tmp_path):
    spec = _spec(ApiSpec(api="list_buckets", result_path="Buckets", id_field="Name"),
                 ApiSpec(api="get_bucket_policy", depends_on=DependsOn(api="list_buckets", params={"Bucket": "Name"})))
    p = tmp_path / "s.yaml"
    dump_spec(spec, p)
    assert load_spec(p) == spec


def test_unknown_field_rejected():
    with pytest.raises(ValidationError):
        ApiSpec.model_validate({"api": "list_buckets", "bogus": 1})


def test_valid_spec_has_no_errors():
    assert validate_spec(_spec(ApiSpec(api="list_buckets", result_path="Buckets"))) == []


def test_mutating_api_is_error():
    issues = validate_spec(_spec(ApiSpec(api="delete_bucket")), check_boto=False)
    assert [i.level for i in issues] == ["error"]


def test_unknown_operation_and_client():
    msgs = [i.message for i in validate_spec(_spec(ApiSpec(api="list_nothing")))]
    assert any("no operation" in m for m in msgs)
    msgs = [i.message for i in validate_spec(_spec(ApiSpec(api="list_buckets"), client="nope"))]
    assert any("unknown boto3 client" in m for m in msgs)


def test_bad_depends_on():
    spec = _spec(ApiSpec(api="get_bucket_policy", depends_on=DependsOn(api="missing")))
    assert any("not in service" in i.message for i in validate_spec(spec, check_boto=False))


def test_duplicate_service():
    spec = CollectSpec(spec_version="t", services=[ServiceSpec(service="a", client="s3"), ServiceSpec(service="a", client="s3")])
    assert any("duplicate" in i.message for i in validate_spec(spec, check_boto=False))


def _svc(*apis, service="kms", client="kms"):
    return CollectSpec(spec_version="t", services=[ServiceSpec(service=service, client=client, apis=list(apis))])


def test_shape_checks_catch_wrong_field_names():
    base = dict(api="list_keys", paginate=True, result_path="Keys", id_field="KeyId", resource_type="key")
    assert validate_spec(_svc(ApiSpec(**base))) == []

    def errors(spec):
        return [i.message for i in validate_spec(spec) if i.level == "error"]

    assert any("result_path 'KeysX'" in m for m in errors(_svc(ApiSpec(**{**base, "result_path": "KeysX"}))))
    assert any("id_field 'KeyIdX'" in m for m in errors(_svc(ApiSpec(**{**base, "id_field": "KeyIdX"}))))
    assert any("arn_field 'Nope'" in m for m in errors(_svc(ApiSpec(**{**base, "arn_field": "Nope"}))))
    child = ApiSpec(api="describe_key", depends_on=DependsOn(api="list_keys", params={"KeyId": "Missing"}))
    assert any("'Missing' is not a member" in m for m in errors(_svc(ApiSpec(**base), child)))


def test_scalar_items_must_use_value_as_their_field():
    root = ApiSpec(api="list_detectors", paginate=True, result_path="DetectorIds", id_field="Value", resource_type="d")
    ok = ApiSpec(api="get_detector", depends_on=DependsOn(api="list_detectors", params={"DetectorId": "Value"}))
    bad = ApiSpec(api="get_detector", depends_on=DependsOn(api="list_detectors", params={"DetectorId": "DetectorIds"}))
    svc = dict(service="guardduty", client="guardduty")
    assert validate_spec(CollectSpec(spec_version="t", services=[ServiceSpec(**svc, apis=[root, ok])])) == []
    msgs = [i.message for i in validate_spec(CollectSpec(spec_version="t", services=[ServiceSpec(**svc, apis=[root, bad])]))]
    assert any("yields scalars" in m for m in msgs)


def test_bad_mask_rule_and_alias_and_as_resource_rules():
    bad_mask = ApiSpec(api="list_keys", result_path="Keys", mask=["wat:x"])
    assert any("bad mask rule" in i.message for i in validate_spec(_svc(bad_mask), check_boto=False))
    dup = _svc(ApiSpec(api="list_keys"), ApiSpec(api="list_keys"))
    assert any("duplicate API key" in i.message for i in validate_spec(dup, check_boto=False))
    aliased = _svc(ApiSpec(api="list_keys"), ApiSpec(api="list_keys", alias="second"))
    assert not any("duplicate" in i.message for i in validate_spec(aliased, check_boto=False))
    loose = _svc(ApiSpec(api="list_keys", as_resource=True))
    assert any("as_resource needs" in i.message for i in validate_spec(loose, check_boto=False))
