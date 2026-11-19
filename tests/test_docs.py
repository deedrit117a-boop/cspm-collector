"""The README is only useful while it matches the code: examples validate, commands exist, links resolve."""
import re
from pathlib import Path

import yaml
from typer.testing import CliRunner

from cspm_collector.cli.main import app
from cspm_collector.core.config import load_settings
from cspm_collector.spec.loader import validate_spec
from cspm_collector.spec.schema import CollectSpec, ServiceSpec

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
DOCS = (ROOT / "docs" / "assumptions-and-open-issues.md").read_text(encoding="utf-8")


def test_new_service_example_in_the_readme_validates():
    section = README.split("### 새 서비스를 추가하려면", 1)[1]
    block = re.search(r"```yaml\n(.*?)```", section, re.S).group(1)
    svc = ServiceSpec.model_validate(yaml.safe_load(block))
    assert validate_spec(CollectSpec(spec_version="t", services=[svc])) == []


def test_every_command_the_readme_mentions_exists():
    commands = set(re.findall(r"\bcollect ([a-z][a-z-]+)", README))
    registered = {c.name or c.callback.__name__.removesuffix("_cmd").replace("_", "-") for c in app.registered_commands}
    assert commands, "no commands found: the pattern is broken"
    assert commands <= registered, sorted(commands - registered)


def test_every_option_in_the_run_table_exists():
    run_help = CliRunner().invoke(app, ["run", "--help"], terminal_width=200).output
    table = README.split("`collect run` 옵션", 1)[1].split("종료 코드", 1)[0]
    for option in set(re.findall(r"`(--[a-z-]+)", table)):
        if option in ("--collect-ecr-images", "--collect-sagemaker-jobs", "--collect-health-check-status"):
            continue  # values of --opt-in, not options of their own
        assert option in run_help, option


def test_local_links_point_to_existing_files():
    for text in (README, DOCS):
        for target in re.findall(r"\]\(([^)#:]+)(?:#[^)]*)?\)", text):
            base = ROOT if text is README else ROOT / "docs"
            assert (base / target).exists(), target


def test_config_example_loads_and_matches_the_readme_keys():
    settings = load_settings(ROOT / "config.example.yaml")
    assert settings.mongo.database == "cspm" and settings.accounts and settings.akamai
    for key in ("external_id_env", "role_arn", "env_prefix", "edge_dns"):
        assert key in README
