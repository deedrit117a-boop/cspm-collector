import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from cspm_collector.core.call import call_api
from cspm_collector.core.errors import Status
from cspm_collector.core.ratelimit import TokenBucket
from cspm_collector.core.stats import Stats


def ce(code):
    return ClientError({"Error": {"Code": code, "Message": "m"}}, "Op")


class FakeClient:
    """Minimal stand-in: no paginator, NextToken pagination, scripted failures."""

    def __init__(self, script):
        self.script, self.seen = list(script), []

    def can_paginate(self, api):
        return False

    def list_things(self, **kw):
        self.seen.append(kw)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_manual_pagination_and_metadata_removed():
    c = FakeClient([{"A": [1], "NextToken": "t1", "ResponseMetadata": {}}, {"A": [2]}])
    r = call_api(c, "svc", "list_things", {"X": 1})
    assert r.ok and r.pages == [{"A": [1], "NextToken": "t1"}, {"A": [2]}]
    assert c.seen == [{"X": 1}, {"X": 1, "NextToken": "t1"}] and r.api_calls == 2


def test_throttle_retried_then_success():
    sleeps = []
    c = FakeClient([ce("Throttling"), ce("Throttling"), {"A": []}])
    r = call_api(c, "svc", "list_things", sleep=sleeps.append)
    assert r.ok and len(sleeps) == 2


def test_throttle_giveup():
    c = FakeClient([ce("Throttling")] * 3)
    r = call_api(c, "svc", "list_things", sleep=lambda s: None)
    assert r.status is Status.THROTTLED_GIVEUP and r.error_code == "Throttling"


def test_empty_config_is_success_with_flag():
    r = call_api(FakeClient([ce("NoSuchBucketPolicy")]), "s3", "list_things")
    assert r.ok and r.empty and r.pages == []


def test_access_denied_not_retried():
    sleeps = []
    r = call_api(FakeClient([ce("AccessDenied")]), "svc", "list_things", sleep=sleeps.append)
    assert r.status is Status.ACCESS_DENIED and not sleeps


@mock_aws
def test_real_paginator_and_stats():
    iam = boto3.client("iam", region_name="us-east-1")
    for i in range(5):
        iam.create_user(UserName=f"u{i}")
    stats = Stats()
    r = call_api(iam, "iam", "list_users", stats=stats)
    assert r.ok
    assert sorted(u["UserName"] for p in r.pages for u in p["Users"]) == [f"u{i}" for i in range(5)]
    assert all("ResponseMetadata" not in p for p in r.pages)
    assert stats.calls == 1 and stats.slowest()[0]["api"] == "list_users"


def test_paginator_used_when_available():
    class Pager:
        def paginate(self, **kw):
            assert kw == {"X": 1}
            yield {"A": [1], "ResponseMetadata": {}}
            yield {"A": [2], "ResponseMetadata": {}}

    class PagedClient:
        def can_paginate(self, api):
            return True

        def get_paginator(self, api):
            return Pager()

    r = call_api(PagedClient(), "svc", "list_things", {"X": 1})
    assert r.ok and r.pages == [{"A": [1]}, {"A": [2]}] and r.api_calls == 2


def test_token_bucket_waits():
    t = [0.0]
    sleeps = []

    def sleep(s):
        sleeps.append(s)
        t[0] += s

    b = TokenBucket(rate=2, burst=1, clock=lambda: t[0], sleep=sleep)
    b.acquire()
    b.acquire()
    assert sleeps and sleeps[0] == pytest.approx(0.5)
