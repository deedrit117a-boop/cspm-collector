import pytest
from botocore.exceptions import ClientError, ConnectTimeoutError, EndpointConnectionError, ReadTimeoutError

from cspm_collector.core.errors import Status, classify_exception, is_throttle


def ce(code):
    return ClientError({"Error": {"Code": code, "Message": "m"}}, "Op")


@pytest.mark.parametrize("code,status", [
    ("AccessDenied", Status.ACCESS_DENIED),
    ("UnauthorizedOperation", Status.ACCESS_DENIED),
    ("InvalidAccessException", Status.NOT_ENABLED),
    ("SubscriptionRequiredException", Status.NOT_ENABLED),
    ("OptInRequired", Status.NOT_SUPPORTED),
    ("ThrottlingException", Status.THROTTLED_GIVEUP),
    ("SomethingNew", Status.ERROR),
])
def test_client_error_codes(code, status):
    c = classify_exception(ce(code), "x")
    assert c.status is status and not c.empty and c.code == code


@pytest.mark.parametrize("code", ["NoSuchBucketPolicy", "NoSuchPublicAccessBlockConfiguration",
                                  "ServerSideEncryptionConfigurationNotFoundError", "ResourceNotFoundException"])
def test_missing_configuration_is_empty_success(code):
    c = classify_exception(ce(code), "s3")
    assert c.status is Status.SUCCESS and c.empty


def test_service_override_beats_global_table():
    assert classify_exception(ce("NoSuchBucket"), "s3").status is Status.ERROR


def test_transport_errors():
    assert classify_exception(ReadTimeoutError(endpoint_url="u")).status is Status.TIMEOUT
    assert classify_exception(ConnectTimeoutError(endpoint_url="u")).status is Status.TIMEOUT
    assert classify_exception(EndpointConnectionError(endpoint_url="u")).status is Status.NOT_SUPPORTED
    assert classify_exception(ValueError("x")).status is Status.ERROR


def test_is_throttle():
    assert is_throttle(ce("Throttling")) and not is_throttle(ce("AccessDenied")) and not is_throttle(ValueError())
