from cspm_collector.core.config import load_settings


def test_defaults_and_env_override(tmp_path, monkeypatch):
    assert load_settings().mongo.database == "cspm"
    monkeypatch.setenv("MONGO_URI", "mongodb://example:1")
    monkeypatch.setenv("MONGO_DATABASE", "other")
    p = tmp_path / "c.yaml"
    p.write_text("accounts:\n  - account_id: '123456789012'\n    regions: [ap-northeast-2]\n", encoding="utf-8")
    s = load_settings(p)
    assert (s.mongo.uri, s.mongo.database) == ("mongodb://example:1", "other")
    assert s.accounts[0].regions == ["ap-northeast-2"]
