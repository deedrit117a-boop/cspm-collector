from datetime import datetime, timezone
from decimal import Decimal

from cspm_collector.storage.normalize import canonical_hash, escape_keys, hash_view, normalize, unescape_keys


def test_normalize_makes_values_bson_and_json_safe():
    raw = {"when": datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc), "blob": b"\x00\x01", "n": Decimal("3"),
           "big": 2**70, "s": {3, 1, 2}, "nested": [{"d": Decimal("1.5")}]}
    out = normalize(raw)
    assert out["when"] == "2026-01-02T03:04:05+00:00"
    assert out["blob"] == "AAE=" and out["n"] == 3 and out["big"] == str(2**70)
    assert out["s"] == [1, 2, 3] and out["nested"] == [{"d": "1.5"}]


def test_hash_ignores_key_order_but_not_values():
    assert canonical_hash({"a": 1, "b": [1, 2]}) == canonical_hash({"b": [1, 2], "a": 1})
    assert canonical_hash({"a": 1}) != canonical_hash({"a": 2})
    assert canonical_hash({"a": [1, 2]}) != canonical_hash({"a": [2, 1]})


def test_escape_roundtrip_for_dots_and_dollars():
    raw = {"aws:SourceArn": 1, "a.b": {"$ref": [{"x.y": 2}]}, "plain": 3}
    esc, changed = escape_keys(raw)
    assert changed
    assert not any("." in k for k in esc) and "$ref" not in esc["a．b"]
    assert unescape_keys(esc) == raw


def test_escape_reports_unchanged():
    assert escape_keys({"a": {"b": 1}}) == ({"a": {"b": 1}}, False)


# ---------------------------------------------------------------------------- policy-aware hash view
def test_reordered_policy_arrays_do_not_change_the_hash():
    import json

    a = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": ["events.amazonaws.com", "sqs.amazonaws.com"]}, "Action": ["sqs:A", "sqs:B"]}]})
    b = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": ["sqs.amazonaws.com", "events.amazonaws.com"]}, "Action": ["sqs:B", "sqs:A"]}]})
    h = lambda doc: canonical_hash(hash_view({"config": {"Attributes": {"Policy": doc}}, "tags": None}))  # noqa: E731
    assert a != b and h(a) == h(b)  # same policy, different text (this is what SQS did between two calls)
    assert h(a) == h(json.loads(b))  # as an object too


def test_real_policy_changes_are_still_changes():
    import json

    def doc(**kw):
        return json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:Get*"], **kw}]})

    h = lambda d: canonical_hash(hash_view({"p": d}))  # noqa: E731
    assert h(doc(Resource="*")) != h(doc(Resource="arn:aws:s3:::b"))
    assert h(doc()) != h(json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": ["s3:Get*"]}]}))
    two = json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "1"}, {"Sid": "2"}]})
    swapped = json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "2"}, {"Sid": "1"}]})
    assert h(two) != h(swapped)  # statement order is kept: only scalar arrays are treated as sets


def test_hash_view_leaves_everything_else_alone():
    data = {"a": [3, 1, 2], "s": '{"not": "a policy"}', "t": "plain", "n": {"x": [{"b": 2}, {"b": 1}]}}
    assert hash_view(data) == data
    assert hash_view('{"Statement": broken json') == '{"Statement": broken json'
