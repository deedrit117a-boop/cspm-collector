from test_web_api import make

from cspm_collector.web.security import LoginThrottle


def test_security_headers_on_page_and_api_and_errors():
    client, *_ = make()
    for path in ("/", "/api/health", "/api/nothing"):
        r = client.get(path)
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert r.headers["referrer-policy"] == "no-referrer"
    assert client.get("/api/health").headers["cache-control"] == "no-store"
    assert client.get("/").headers["cache-control"] == "no-store"
    # nothing is loaded from other hosts, so the policy must not list any
    assert "http" not in client.get("/").headers["content-security-policy"]


def test_wrong_token_locks_the_client_and_is_audited():
    client, rt, _stub, store = make(token="s3cret")
    for _ in range(4):
        assert client.get("/api/overview", headers={"authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/overview", headers={"authorization": "Bearer nope"}).status_code == 401  # the 5th locks
    locked = client.get("/api/overview", headers={"authorization": "Bearer s3cret"})
    assert locked.status_code == 429 and int(locked.headers["retry-after"]) > 0
    assert store.coll("audit").count_documents({"action": "auth_locked"}) == 1


def test_right_token_resets_the_count():
    client, *_ = make(token="s3cret")
    for _ in range(4):
        client.get("/api/overview", headers={"authorization": "Bearer nope"})
    assert client.get("/api/overview", headers={"authorization": "Bearer s3cret"}).status_code == 200
    for _ in range(4):
        assert client.get("/api/overview", headers={"authorization": "Bearer nope"}).status_code == 401


def test_throttle_window_lock_and_memory_bound():
    t = [0.0]
    th = LoginThrottle(clock=lambda: t[0], max_failures=3, window=60, lock=120)
    th.failed("a"); th.failed("a")
    t[0] = 61  # the first two aged out of the window
    assert not th.failed("a") and th.locked("a") == 0
    th.failed("a")
    assert th.failed("a") or th.locked("a")
    assert th.locked("a") > 0
    t[0] += 121
    assert th.locked("a") == 0
    for i in range(1500):
        th.failed(f"c{i}")
    assert len(th._fails) <= 1000
