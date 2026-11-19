import pytest

from cspm_collector.collectors.masking import apply_mask, parse_rule
from cspm_collector.core.secrets import MASK

SECRET = "hunter2hunter2"


def test_rule_syntax_errors():
    for bad in ("nope:x", "value:", "pairs:a|b", "pairs:a|b|c|d|e", "x"):
        with pytest.raises(ValueError):
            parse_rule(bad)
    assert parse_rule("pairs:a.b[]|Name|Value|Ns=x")[0] == "pairs"


def test_value_masks_and_reports_type_and_line():
    obj = {"definition": f"line one\nexport DB_PASSWORD={SECRET}\n", "name": "sm"}
    findings = apply_mask(obj, "value:definition", "svc.sm")
    assert obj == {"definition": MASK, "name": "sm"}
    assert findings == [{"location": "svc.sm.definition", "type": "password_assignment", "line": 2}]
    assert SECRET not in str(findings)


def test_b64_decodes_before_scanning():
    import base64

    obj = {"OnCreate": [{"Content": base64.b64encode(f"password={SECRET}".encode()).decode()}, {"Content": ""}]}
    findings = apply_mask(obj, "b64:OnCreate[].Content", "nb")
    assert obj["OnCreate"][0]["Content"] == MASK and obj["OnCreate"][1]["Content"] == ""  # empty stays empty
    assert [f["type"] for f in findings] == ["password_assignment"]


def test_map_masks_every_value_but_keeps_names():
    obj = {"Environment": {"API_KEY": SECRET, "MODE": "prod"}}
    findings = apply_mask(obj, "map:Environment", "model")
    assert obj["Environment"] == {"API_KEY": MASK, "MODE": MASK}
    assert findings == [{"location": "model.Environment.API_KEY", "type": "secret_assignment"}]


def test_smap_masks_only_secret_looking_entries():
    obj = {"DefaultArguments": {"--password": SECRET, "--enable-metrics": "true"}}
    apply_mask(obj, "smap:DefaultArguments", "job")
    assert obj["DefaultArguments"] == {"--password": MASK, "--enable-metrics": "true"}


def test_pairs_through_nested_lists_and_filter():
    obj = {"taskDefinition": {"containerDefinitions": [
        {"name": "a", "environment": [{"name": "DB_PASSWORD", "value": SECRET}, {"name": "MODE", "value": "prod"}]},
        {"name": "b", "environment": [{"name": "X", "value": "y"}]}]}}
    findings = apply_mask(obj, "pairs:taskDefinition.containerDefinitions[].environment|name|value", "td")
    values = [e["value"] for c in obj["taskDefinition"]["containerDefinitions"] for e in c["environment"]]
    assert values == [MASK, MASK, MASK]
    assert findings == [{"location": "td.taskDefinition.containerDefinitions[].environment.DB_PASSWORD",
                         "type": "password_assignment"}]

    opts = {"OptionSettings": [{"Namespace": "ns:env", "OptionName": "TOKEN", "Value": SECRET},
                               {"Namespace": "ns:other", "OptionName": "Port", "Value": "80"}]}
    apply_mask(opts, "pairs:OptionSettings|OptionName|Value|Namespace=ns:env", "eb")
    assert [o["Value"] for o in opts["OptionSettings"]] == [MASK, "80"]


def test_spairs_is_selective():
    obj = {"Parameters": [{"ParameterKey": "DbPassword", "ParameterValue": f"password={SECRET}"},
                          {"ParameterKey": "Env", "ParameterValue": "prod"}]}
    apply_mask(obj, "spairs:Parameters|ParameterKey|ParameterValue", "stack")
    assert [p["ParameterValue"] for p in obj["Parameters"]] == [MASK, "prod"]


def test_missing_paths_and_odd_types_are_ignored():
    obj = {"a": None, "b": "text", "c": {"d": 1}}
    for rule in ("map:nope", "pairs:a|n|v", "map:b", "pairs:c.d|n|v", "value:zzz.yy", "pairs:q[].r|n|v"):
        assert apply_mask(obj, rule, "x") == []
    assert obj == {"a": None, "b": "text", "c": {"d": 1}}
