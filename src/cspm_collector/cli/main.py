"""``collect`` command line."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from pymongo import MongoClient

from cspm_collector.akamai.client import EdgeGridClient
from cspm_collector.collectors.base import CollectOptions
from cspm_collector.core.config import load_settings
from cspm_collector.core.scan import ScanFilter, plan_retry, run_scan
from cspm_collector.core.tls import build_ca_bundle
from cspm_collector.spec.assemble import assemble, load_overrides
from cspm_collector.spec.builder import build_spec, read_prowler_version
from cspm_collector.spec.iam_policy import policy_documents
from cspm_collector.spec.loader import dump_spec, load_spec, validate_spec
from cspm_collector.storage.store import Store, rename_collections

app = typer.Typer(no_args_is_help=True, help="Read-only AWS/Akamai collector.")

GENERATED = Path("spec/collect_spec.generated.yaml")
ACTIVE = Path("spec/collect_spec.yaml")


def _csv(value: Optional[str]) -> set[str] | None:
    return {v.strip() for v in value.split(",") if v.strip()} if value else None


def _store(config: Optional[Path]):
    settings = load_settings(config)
    db = MongoClient(settings.mongo.uri)[settings.mongo.database]
    return settings, Store(db, settings.mongo)


@app.command("build-spec")
def build_spec_cmd(
    prowler_root: Path = typer.Option(..., help="Directory containing the 'prowler' package."),
    rules: Path = typer.Option(..., help="rules_master.json"),
    out_yaml: Path = typer.Option(GENERATED),
    out_report: Path = typer.Option(Path("spec/collection_spec_report.json")),
) -> None:
    """Generate a draft spec from the Prowler sources (reference only; see assemble-spec)."""
    services_dir = prowler_root / "prowler" / "providers" / "aws" / "services"
    if not services_dir.is_dir():
        raise typer.BadParameter(f"{services_dir} not found; pass the directory that contains the 'prowler' package")
    spec, report = build_spec(services_dir, rules, read_prowler_version(prowler_root))
    out_yaml.parent.mkdir(parents=True, exist_ok=True)
    dump_spec(spec, out_yaml)
    out_report.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    n_apis = sum(len(s.apis) for s in spec.services)
    review = sum(a.needs_review for s in spec.services for a in s.apis)
    typer.echo(f"{len(spec.services)} services, {n_apis} apis ({review} need review) -> {out_yaml}")
    typer.echo(f"spec_version={spec.spec_version} prowler_version={spec.prowler_version}")


@app.command("assemble-spec")
def assemble_spec_cmd(
    generated: Path = typer.Option(GENERATED),
    overrides: Path = typer.Option(Path("spec/overrides"), help="Directory of curated <service>.yaml files."),
    out_yaml: Path = typer.Option(ACTIVE),
) -> None:
    """Merge generated spec + curated overrides into the active collect_spec.yaml."""
    spec = assemble(load_spec(generated), load_overrides(overrides))
    dump_spec(spec, out_yaml)
    on = [s.service for s in spec.services if s.enabled]
    typer.echo(f"{len(spec.services)} services ({len(on)} enabled: {', '.join(on)}) -> {out_yaml}")


@app.command("validate-spec")
def validate_spec_cmd(
    spec_path: Path = typer.Argument(ACTIVE),
    offline: bool = typer.Option(False, help="Skip checks against botocore service models."),
) -> None:
    """Validate the spec: schema, read-only API names, botocore operations."""
    issues = validate_spec(load_spec(spec_path), check_boto=not offline)
    for i in issues:
        typer.echo(f"{i.level.upper():7} {i.where}: {i.message}")
    errors = sum(i.level == "error" for i in issues)
    typer.echo(f"{errors} errors, {len(issues) - errors} warnings")
    raise typer.Exit(1 if errors else 0)


@app.command("list-spec")
def list_spec_cmd(
    spec_path: Path = typer.Argument(ACTIVE),
    tier: Optional[int] = typer.Option(None, help="Only this tier."),
    services: Optional[str] = typer.Option(None, help="Comma-separated service names."),
    enabled_only: bool = typer.Option(False, help="Hide disabled services."),
) -> None:
    """Print services and their APIs."""
    wanted = _csv(services)
    for s in load_spec(spec_path).services:
        if (tier and s.tier != tier) or (wanted and s.service not in wanted) or (enabled_only and not s.enabled):
            continue
        off = "" if s.enabled else " [disabled]"
        typer.echo(f"[T{s.tier}] {s.service} ({s.scope}, {s.collector}, rules={s.rule_count}){off} {len(s.apis)} apis")
        for a in s.apis:
            flag = " ?" if a.needs_review else ""
            dep = f" <- {a.depends_on.api}" if a.depends_on else ""
            typer.echo(f"    {a.client or s.client}.{a.api}{dep}{flag}")


@app.command("iam-policy")
def iam_policy_cmd(
    spec_path: Path = typer.Argument(ACTIVE),
    out_dir: Path = typer.Option(Path("iam"), help="Directory for the generated policy-<n>.json files."),
    all_services: bool = typer.Option(False, "--all", help="Include disabled services too."),
) -> None:
    """Write the read-only IAM policy (split into <=6000 character documents) the enabled spec needs."""
    docs = policy_documents(load_spec(spec_path), enabled_only=not all_services)
    out_dir.mkdir(parents=True, exist_ok=True)
    for n, doc in enumerate(docs, start=1):
        (out_dir / f"policy-{n}.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    total = sum(len(d["Statement"][0]["Action"]) for d in docs)
    typer.echo(f"{total} actions in {len(docs)} policies -> {out_dir}  (attach them, or use SecurityAudit + this)")


@app.command("ensure-indexes")
def ensure_indexes_cmd(config: Optional[Path] = typer.Option(None, help="config.yaml")) -> None:
    """Create collections' indexes (refuses a database with foreign same-named collections)."""
    settings, store = _store(config)
    store.init_db()
    typer.echo(f"indexes ready in database '{settings.mongo.database}'")


@app.command("run")
def run_cmd(
    config: Optional[Path] = typer.Option(None, help="config.yaml (accounts, mongo, concurrency)"),
    spec_path: Path = typer.Option(ACTIVE, "--spec"),
    services: Optional[str] = typer.Option(None, help="Comma-separated services, e.g. s3,iam"),
    tier: Optional[int] = typer.Option(None, help="Only services of this tier."),
    regions: Optional[str] = typer.Option(None, help="Comma-separated regions."),
    accounts: Optional[str] = typer.Option(None, help="Comma-separated account ids."),
    collect_userdata: bool = typer.Option(False, "--collect-userdata",
                                          help="Scan EC2 UserData for secrets (content is always masked)."),
    opt_in: list[str] = typer.Option([], "--opt-in", help="Enable an opt-in API flag, e.g. --collect-lookup-events"),
    retry_failed: Optional[str] = typer.Option(None, "--retry-failed", metavar="SCAN_ID",
                                               help="Only redo the (account, region, service) ranges that failed in this scan."),
) -> None:
    """Collect and store one scan."""
    settings, store = _store(config)
    if not settings.accounts and not settings.akamai:
        raise typer.BadParameter("no AWS accounts or Akamai accounts configured")
    spec = load_spec(spec_path)
    errors = [i for i in validate_spec(spec) if i.level == "error"]
    if errors:
        for i in errors:
            typer.echo(f"ERROR {i.where}: {i.message}", err=True)
        raise typer.Exit(2)
    store.init_db()
    flags = set(opt_in) | ({"--collect-userdata"} if collect_userdata else set())
    plan = None
    if retry_failed:
        try:
            plan = plan_retry(store, retry_failed)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        typer.echo(f"retrying {len(plan.tasks)} ranges, {len(plan.accounts)} accounts, {len(plan.akamai)} akamai accounts "
                   f"from scan {retry_failed}")
    summary = run_scan(
        settings, spec, store,
        flt=ScanFilter(_csv(services), tier, _csv(regions), _csv(accounts), plan),
        options=CollectOptions(flags=frozenset(flags)),
    )
    typer.echo(f"scan {summary.scan_id}: {summary.status}; {summary.tasks} tasks; resources {vars(summary.resources)}; "
               f"akamai {vars(summary.akamai_resources)}; swept {summary.swept}; statuses {dict(summary.statuses)}")
    typer.echo(summary.stats.summary())
    raise typer.Exit(0 if summary.status != "FAILED" else 1)


@app.command("akamai-check")
def akamai_check_cmd(config: Optional[Path] = typer.Option(None, help="config.yaml")) -> None:
    """Verify every configured Akamai API client with one read-only call (PAPI groups)."""
    settings = load_settings(config)
    if not settings.akamai:
        raise typer.BadParameter("no akamai accounts configured")
    failed = False
    for acct in settings.akamai:
        try:
            data = EdgeGridClient.from_settings(acct).get("/papi/v1/groups")
            n = len(((data.get("groups") or {}).get("items")) or [])
            typer.echo(f"OK   {acct.name}: {n} groups visible")
        except Exception as exc:  # noqa: BLE001 - report and keep checking the other accounts
            failed = True
            typer.echo(f"FAIL {acct.name}: {type(exc).__name__}: {exc}", err=True)
    raise typer.Exit(1 if failed else 0)


@app.command("web")
def web_cmd(
    config: Optional[Path] = typer.Option(None, help="config.yaml"),
    host: str = typer.Option("127.0.0.1", help="Address to listen on. Anything but localhost needs protection."),
    port: int = typer.Option(8765),
    token_env: str = typer.Option("CSPM_WEB_TOKEN", help="Name of the env var holding the access token."),
    user_header: Optional[str] = typer.Option(None, help="Header with the user name set by an SSO proxy, e.g. X-Forwarded-User."),
    allow_host: list[str] = typer.Option([], "--allow-host", help="Host name the page is reached by (repeatable)."),
    no_auth: bool = typer.Option(False, "--no-auth", help="Allow a non-localhost address without a token (only behind a trusted proxy)."),
) -> None:
    """Start the control page: choose items, schedules, run now, see counts and durations."""
    import os

    import uvicorn

    from cspm_collector.web.server import build_runtime

    loopback = host in ("127.0.0.1", "localhost", "::1")
    token = os.environ.get(token_env) or None
    if not loopback and not (token or user_header or no_auth):
        raise typer.BadParameter(
            f"{host} is reachable from other machines: set {token_env}, or run behind an SSO proxy with --user-header, "
            f"or pass --no-auth if a trusted proxy already protects it")
    settings, store = _store(config)
    store.init_db()
    hosts = ("127.0.0.1", "localhost", "[::1]", *allow_host)
    rt = build_runtime(settings, store, token=token, user_header=user_header, allowed_hosts=hosts, preflight_on=True)
    rt.start()
    typer.echo(f"control page: http://{'localhost' if loopback else host}:{port}  "
               f"(auth: {'token' if token else 'proxy header' if user_header else 'none, localhost only' if loopback else 'none'})")
    try:
        uvicorn.run(rt.app, host=host, port=port, log_level="warning", server_header=False)
    finally:
        rt.stop()


@app.command("export-ca-bundle")
def export_ca_bundle_cmd(out: Path = typer.Option(Path("ca-bundle.pem"), help="Where to write the PEM bundle.")) -> None:
    """Write certifi + the operating system's trusted CAs for TLS-inspecting proxies (see core/tls.py)."""
    base, extra = build_ca_bundle(out)
    typer.echo(f"{out}: {base} bundled + {extra} system certificates")
    typer.echo(f"use it with:  $env:AWS_CA_BUNDLE = '{out.resolve()}'   (and REQUESTS_CA_BUNDLE for Akamai)")


@app.command("rename-collections")
def rename_collections_cmd(
    to_prefix: str = typer.Option(..., help='New prefix, e.g. "000_" (so they sort first in Compass).'),
    from_prefix: str = typer.Option("", help="Current prefix of the collections."),
    config: Optional[Path] = typer.Option(None, help="config.yaml"),
) -> None:
    """Rename this collector's own collections to a new prefix, keeping data and indexes."""
    settings, store = _store(config)
    try:
        renamed = rename_collections(store.db, from_prefix, to_prefix)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    for old, new in renamed:
        typer.echo(f"{old} -> {new}")
    typer.echo(f"{len(renamed)} collections renamed in '{settings.mongo.database}'. Set mongo.collection_prefix: "
               f"'{to_prefix}' (or MONGO_COLLECTION_PREFIX) so the collector uses the new names.")


@app.command("status")
def status_cmd(scan_id: str, config: Optional[Path] = typer.Option(None)) -> None:
    """Show a scan and every non-SUCCESS collection_status row."""
    _, store = _store(config)
    scan = store.coll("scans").find_one({"scan_id": scan_id}, {"_id": 0})
    if not scan:
        raise typer.BadParameter(f"unknown scan {scan_id}")
    typer.echo(json.dumps(scan, default=str, indent=1, ensure_ascii=False))
    for r in store.coll("collection_status").find({"scan_id": scan_id, "status": {"$ne": "SUCCESS"}}):
        typer.echo(f"{r['status']:16} {r['account_id']} {r['region']} {r['service']}.{r['api']} "
                   f"{r.get('error_code') or ''} {r.get('error') or ''}")


if __name__ == "__main__":
    app()
