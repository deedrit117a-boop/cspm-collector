import json

import pytest
import requests

from cspm_collector.akamai.client import AkamaiHttpError, EdgeGridClient, classify_http_error
from cspm_collector.core.config import AkamaiAccountSettings
from cspm_collector.core.errors import Status


class Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self.headers = status, headers or {}
        self.content = json.dumps(body).encode() if body is not None else b""
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class ScriptedSession:
    def __init__(self, *responses):
        self.responses, self.requests, self.auth = list(responses), [], None

    def get(self, url, params=None, headers=None, timeout=None):
        self.requests.append((url, dict(params or {}), headers, timeout))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def client(session, **kw):
    sleeps: list[float] = []
    kw.setdefault("requests_per_second", 1000)
    c = EdgeGridClient("https://akab-host.luna.akamaiapis.net", auth=object(), session=session, sleep=sleeps.append, **kw)
    return c, sleeps


def test_success_joins_url_and_sends_timeout():
    s = ScriptedSession(Resp(200, {"ok": 1}))
    c, _ = client(s)
    assert c.get("/papi/v1/groups", {"a": 1}) == {"ok": 1}
    url, params, _, timeout = s.requests[0]
    assert url == "https://akab-host.luna.akamaiapis.net/papi/v1/groups" and params == {"a": 1} and timeout == (5, 60)


def test_429_honours_retry_after_then_succeeds():
    s = ScriptedSession(Resp(429, {}, {"Retry-After": "7"}), Resp(200, {"ok": 1}))
    c, sleeps = client(s)
    assert c.get("/x") == {"ok": 1}
    assert 7.0 in sleeps and len(s.requests) == 2


def test_5xx_backs_off_with_growing_delay_then_gives_up():
    s = ScriptedSession(*[Resp(503, {}) for _ in range(3)])
    c, sleeps = client(s, max_retries=2)
    with pytest.raises(AkamaiHttpError) as err:
        c.get("/x")
    assert err.value.status == 503 and len(s.requests) == 3
    assert [d for d in sleeps if d >= 5] == [5.0, 15.0]  # a few seconds, +10s per retry (Akamai's guidance)
    assert classify_http_error(err.value) is Status.ERROR


@pytest.mark.parametrize("status,expected", [(401, Status.ACCESS_DENIED), (403, Status.ACCESS_DENIED),
                                             (404, Status.ERROR), (429, Status.THROTTLED_GIVEUP)])
def test_client_errors_are_not_retried_and_are_classified(status, expected):
    s = ScriptedSession(Resp(status, {"type": "x/forbidden"}) if status != 429 else Resp(429, {}))
    c, sleeps = client(s, max_retries=0 if status == 429 else 3)
    with pytest.raises(AkamaiHttpError) as err:
        c.get("/x")
    assert len(s.requests) == 1 and classify_http_error(err.value) is expected


def test_account_switch_key_is_sent_but_never_shown_in_errors():
    s = ScriptedSession(Resp(403, {"detail": "nope"}))
    c, _ = client(s, account_switch_key="SECRET-SWITCH-KEY")
    with pytest.raises(AkamaiHttpError) as err:
        c.get("/papi/v1/groups", {"contractId": "ctr_1"})
    assert s.requests[0][1] == {"contractId": "ctr_1", "accountSwitchKey": "SECRET-SWITCH-KEY"}
    assert "SECRET-SWITCH-KEY" not in str(err.value) and "SECRET-SWITCH-KEY" not in repr(err.value.__dict__)


def test_timeouts_and_connection_errors_classify():
    assert classify_http_error(requests.Timeout()) is Status.TIMEOUT
    assert classify_http_error(requests.ConnectionError()) is Status.ERROR
    assert classify_http_error(ValueError()) is Status.ERROR


def test_rate_limit_spaces_requests():
    t = [0.0]
    slept: list[float] = []

    def sleep(x):
        slept.append(x)
        t[0] += x

    s = ScriptedSession(*[Resp(200, {}) for _ in range(6)])
    c = EdgeGridClient("https://h", auth=object(), session=s, requests_per_second=1, sleep=sleep)
    c._bucket._clock = lambda: t[0]
    for _ in range(6):
        c.get("/x")
    assert sum(slept) >= 3.0  # burst of 2, then one request per second


# ------------------------------------------------------------------------------ credentials
def test_credentials_from_environment(monkeypatch):
    cfg = AkamaiAccountSettings(name="a", env_prefix="AKAMAI_T", account_switch_key_env="AKAMAI_T_SWITCH")
    for n in ("HOST", "CLIENT_TOKEN", "CLIENT_SECRET", "ACCESS_TOKEN"):
        monkeypatch.setenv(f"AKAMAI_T_{n}", f"v-{n}")
    monkeypatch.delenv("AKAMAI_T_SWITCH", raising=False)
    with pytest.raises(RuntimeError, match="AKAMAI_T_SWITCH"):
        EdgeGridClient.from_settings(cfg)
    monkeypatch.setenv("AKAMAI_T_SWITCH", "1-ABCDE")
    c = EdgeGridClient.from_settings(cfg)
    assert c.base_url == "https://v-HOST"


def test_missing_environment_names_the_variables_not_values(monkeypatch):
    cfg = AkamaiAccountSettings(name="a", env_prefix="AKAMAI_NOPE")
    monkeypatch.setenv("AKAMAI_NOPE_CLIENT_SECRET", "do-not-print-me")
    with pytest.raises(RuntimeError) as err:
        EdgeGridClient.from_settings(cfg)
    assert "AKAMAI_NOPE_HOST" in str(err.value) and "do-not-print-me" not in str(err.value)


def test_credentials_from_edgerc_section(tmp_path):
    rc = tmp_path / "edgerc"
    rc.write_text("[prod]\nclient_secret = cs\nhost = akab-xyz.luna.akamaiapis.net\naccess_token = at\nclient_token = ct\n",
                  encoding="utf-8")
    c = EdgeGridClient.from_settings(AkamaiAccountSettings(name="a", edgerc=str(rc), section="prod"))
    assert c.base_url == "https://akab-xyz.luna.akamaiapis.net"
    with pytest.raises(RuntimeError, match="edgerc or env_prefix"):
        EdgeGridClient.from_settings(AkamaiAccountSettings(name="b"))
