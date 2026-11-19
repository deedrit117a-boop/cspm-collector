"""Used-region detection: free probes per enabled region; a region that cannot be probed is "unknown", never "unused"."""
import pytest
from botocore.exceptions import ClientError

from cspm_collector.core import regions as mod
from cspm_collector.core.regions import UNKNOWN, UNUSED, USED, detect_used_regions
from test_web_accounts import OK
from test_web_api import UI, make

DENY = ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}}, "Op")


class Client:
    """A boto client double: ``has`` names what exists in the region, ``deny`` makes every call fail."""

    def __init__(self, has=(), deny=False):
        self.has, self.deny = set(has), deny

    def _check(self):
        if self.deny:
            raise DENY

    def describe_network_interfaces(self, **kw):
        self._check()
        return {"NetworkInterfaces": [{}] if "eni" in self.has else []}

    def describe_vpcs(self, **kw):
        self._check()
        return {"Vpcs": [{}] if "vpc" in self.has else []}

    def describe_instances(self, **kw):
        self._check()
        return {"Reservations": [{"Instances": [{}]}] if "ec2" in self.has else []}

    def list_queues(self, **kw):
        self._check()
        return {"QueueUrls": ["u"]} if "sqs" in self.has else {}

    def list_topics(self, **kw):
        self._check()
        return {"Topics": [{}] if "sns" in self.has else []}

    def list_functions(self, **kw):
        self._check()
        return {"Functions": []}

    def list_tables(self, **kw):
        self._check()
        return {"TableNames": []}


class Sess:
    def __init__(self, world):
        self.world, self.calls = world, []

    def enabled_regions(self, include_opt_in=True):
        return sorted(self.world)

    def client(self, service, region):
        self.calls.append((service, region))
        return self.world[region]


WORLD = {"ap-northeast-2": Client({"eni", "ec2"}), "us-east-1": Client(), "ap-southeast-1": Client({"sqs"}),
         "eu-west-1": Client(deny=True), "ca-central-1": Client()}


def test_regions_are_used_unused_or_unknown_and_unknown_is_never_called_unused():
    d = detect_used_regions(Sess(WORLD))
    state = {r.region: r.state for r in d.regions}
    assert state == {"ap-northeast-2": USED, "ap-southeast-1": USED, "us-east-1": UNUSED, "ca-central-1": UNUSED,
                     "eu-west-1": UNKNOWN}
    seoul = next(r for r in d.regions if r.region == "ap-northeast-2")
    assert seoul.evidence == ["네트워크 인터페이스", "EC2 인스턴스"]
    denied = next(r for r in d.regions if r.region == "eu-west-1")
    assert set(denied.errors) == {p.key for p in mod.PROBES} and denied.errors["eni"] == "ClientError"
    assert d.collect == ["ap-northeast-2", "ap-southeast-1"]  # the unknown region is reported, not added silently


def test_pinned_regions_are_kept_even_when_nothing_was_found():
    d = detect_used_regions(Sess(WORLD), always=("us-east-1", "eu-west-1"))
    assert set(d.collect) == {"ap-northeast-2", "ap-southeast-1", "eu-west-1", "us-east-1"}
    assert d.by_state(UNUSED) == ["ca-central-1", "us-east-1"]


def test_probes_are_only_list_calls_with_one_page():
    """Nothing but cheap list/describe calls: no write verbs and no cost-bearing API."""
    import inspect
    src = inspect.getsource(mod)
    assert "ce" not in {p.client for p in mod.PROBES}
    for verb in (".create", ".put", ".delete", ".update", ".start", ".stop", ".run_"):
        assert verb not in src


# ----------------------------------------------------------------------------- the web endpoint
@pytest.fixture
def web():
    client, rt, stub, store = make()
    yield client, rt
    rt.stop()


def test_endpoint_returns_the_detection_and_keeps_typed_regions_pinned(web, monkeypatch):
    client, _ = web
    seen = {}

    def fake(account, always):
        seen["account"], seen["always"] = account, always
        return detect_used_regions(Sess(WORLD), always=always)

    monkeypatch.setattr("cspm_collector.web.app.detect_regions", fake)
    r = client.post("/api/accounts/detect-regions", json={**OK, "role_arn": None, "external_id_env": None,
                                                         "regions": ["us-east-1"]}, headers=UI)
    assert r.status_code == 200
    body = r.json()
    assert body["used"] == ["ap-northeast-2", "ap-southeast-1"] and body["unknown"] == ["eu-west-1"]
    assert set(body["collect"]) == {"ap-northeast-2", "ap-southeast-1", "us-east-1"}
    assert seen["always"] == ("us-east-1",) and seen["account"].account_id == OK["account_id"]
    assert any(a["action"] == "account_detect_regions" for a in client.get("/api/audit").json()["entries"])


def test_endpoint_explains_a_failure_and_needs_the_ui_header(web, monkeypatch):
    client, _ = web

    def boom(account, always):
        raise RuntimeError("env var CSPM_EXTID_GAME is not set")

    monkeypatch.setattr("cspm_collector.web.app.detect_regions", boom)
    body = {**OK}
    assert client.post("/api/accounts/detect-regions", json=body).status_code == 403  # no X-CSPM-UI header
    r = client.post("/api/accounts/detect-regions", json=body, headers=UI)
    assert r.status_code == 422 and "CSPM_EXTID_GAME" in r.json()["detail"]


# ----------------------------------------------------------------------------- many accounts at once
def wait_done(client, timeout=10):
    import time
    end = time.time() + timeout
    while time.time() < end:
        job = client.get("/api/accounts/regions/detect").json()["job"]
        if job and job["state"] == "done":
            return job
        time.sleep(0.05)
    raise AssertionError("the detection did not finish")


def test_batch_detects_every_account_keeps_the_result_and_applies_only_what_may_change(web, monkeypatch):
    client, _ = web
    web_acct = {**OK, "role_arn": None, "external_id_env": None, "regions": ["ap-northeast-2"]}
    assert client.post("/api/accounts", json=web_acct, headers=UI).status_code == 201
    quiet = {**web_acct, "account_id": "555566667777", "name": "quiet", "regions": ["us-east-1"]}
    assert client.post("/api/accounts", json=quiet, headers=UI).status_code == 201
    seen = []

    def fake(account, always):
        seen.append((account.account_id, always))
        if account.account_id == "555566667777":
            raise RuntimeError("env var CSPM_EXTID_X is not set")
        world = {"ap-northeast-2": Client({"eni"}), "ap-northeast-1": Client({"sqs"}), "us-east-1": Client()}
        return detect_used_regions(Sess(world), always=always)

    monkeypatch.setattr("cspm_collector.web.app.detect_regions", fake)
    r = client.post("/api/accounts/regions/detect", json={}, headers=UI)
    assert r.status_code == 202 and r.json()["started"] is True
    job = wait_done(client)
    assert (job["total"], job["ok"], job["failed"]) == (3, 2, 1)
    res = client.get("/api/accounts/regions/detect").json()["results"]
    assert res[OK["account_id"]]["collect"] == ["ap-northeast-1", "ap-northeast-2"] and res["111"]["ok"] is True
    assert res[OK["account_id"]]["current"] == ["ap-northeast-2"]  # what is set now, shown next to the result
    assert res["555566667777"]["ok"] is False and res["555566667777"]["code"] == "EXTERNAL_ID_ENV_MISSING"  # same reasons as the connection check
    assert (OK["account_id"], ("ap-northeast-2",)) in seen  # the regions set now are pinned

    a = client.post("/api/accounts/regions/apply", json={"account_ids": [OK["account_id"], "111", "555566667777", "000000000000"]},
                    headers=UI).json()
    assert a["applied"] == {OK["account_id"]: ["ap-northeast-1", "ap-northeast-2"]}
    assert "config.yaml" in a["skipped"]["111"] and "실패" in a["skipped"]["555566667777"] and "000000000000" in a["skipped"]
    acc = {x["account_id"]: x for x in client.get("/api/overview").json()["accounts"]}
    assert acc[OK["account_id"]]["regions"] == ["ap-northeast-1", "ap-northeast-2"] and acc["111"]["regions"] == ["ap-northeast-2", "us-east-1"]


def test_an_empty_detection_is_never_written_because_empty_means_all_regions(web, monkeypatch):
    client, _ = web
    client.post("/api/accounts", json={**OK, "role_arn": None, "external_id_env": None, "regions": ["us-east-1"]}, headers=UI)
    monkeypatch.setattr("cspm_collector.web.app.detect_regions",
                        lambda account, always: detect_used_regions(Sess({"ap-northeast-2": Client()}), always=()))
    client.post("/api/accounts/regions/detect", json={"account_ids": [OK["account_id"]]}, headers=UI)
    wait_done(client)
    a = client.post("/api/accounts/regions/apply", json={"account_ids": [OK["account_id"]]}, headers=UI).json()
    assert a["applied"] == {} and "바꾸지 않음" in a["skipped"][OK["account_id"]]


def test_batch_validates_its_input(web):
    client, _ = web
    assert client.post("/api/accounts/regions/detect", json={"account_ids": []}, headers=UI).status_code == 422
    assert client.post("/api/accounts/regions/detect", json={"account_ids": ["999999999999"]}, headers=UI).status_code == 422
    assert client.post("/api/accounts/regions/detect", json={}).status_code == 403  # needs the UI header
