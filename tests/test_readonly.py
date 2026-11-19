import pytest

from cspm_collector.spec.readonly import check_api_name


@pytest.mark.parametrize("api", ["describe_instances", "list_buckets", "get_bucket_policy",
                                 "batch_get_something", "generate_credential_report"])
def test_allowed(api):
    assert check_api_name(api, None) is None


@pytest.mark.parametrize("api", ["delete_bucket", "put_bucket_policy", "create_user",
                                 "terminate_instances", "update_trail", "attach_role_policy"])
def test_mutating_blocked(api):
    level, _ = check_api_name(api, None)
    assert level == "error"


def test_opt_in_required():
    assert check_api_name("lookup_events", None)[0] == "error"
    assert check_api_name("lookup_events", "--collect-lookup-events") is None


def test_unknown_name_warns():
    assert check_api_name("frobnicate", None)[0] == "warning"
