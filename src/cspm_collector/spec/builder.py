"""Derive a draft collection spec from the Prowler source tree.

Prowler never gets executed: each ``*_service.py`` is parsed with ``ast`` and the
boto3 calls it makes are mapped onto botocore's service models. The output is a
*draft* -- values that had to be guessed are flagged ``needs_review``.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from . import botomodel
from .readonly import ALLOWED_EXACT, OPT_IN_ONLY
from .schema import ApiSpec, CollectSpec, DependsOn, ServiceSpec

# Prowler service directory -> boto3 client name (only where they differ).
CLIENT_NAMES = {
    "acmpca": "acm-pca",
    "awslambda": "lambda",
    "cognito": "cognito-idp",
    "directoryservice": "ds",
    "documentdb": "docdb",
    "eventbridge": "events",
    "macie": "macie2",
    "networkfirewall": "network-firewall",
    "resourceexplorer2": "resource-explorer-2",
    "ssmincidents": "ssm-incidents",
    "trustedadvisor": "support",
    "vpc": "ec2",
}

# Prowler services that also call a second boto3 client without naming it literally.
EXTRA_CLIENTS = {
    "bedrock": {"bedrock-agent"},
    "dlm": {"ec2"},
    "dynamodb": {"dax"},
    "eventbridge": {"schemas"},
    "kafka": {"kafkaconnect"},
    "route53": {"route53domains", "ec2"},
    "s3": {"s3control"},
    "ses": {"sesv2"},
    "waf": {"waf-regional"},
}

# Called once per account (not per region). Prowler only flags 4 of these itself.
GLOBAL_SERVICES = {"iam", "route53", "cloudfront", "organizations", "shield", "fms", "account", "s3"}

TIER1 = {
    "iam", "ec2", "vpc", "s3", "cloudtrail", "cloudwatch", "rds", "kms", "account",
    "accessanalyzer", "config", "securityhub", "macie", "guardduty", "inspector2",
    "organizations", "awslambda", "apigateway", "apigatewayv2", "cloudfront", "elbv2",
    "route53", "efs", "glacier", "sns", "sqs", "secretsmanager", "eventbridge",
    "waf", "wafv2", "elb", "autoscaling", "acm",
}

# Services that need a hand-written collector; everything else is "generic".
CUSTOM_COLLECTORS = {
    "iam": "iam", "s3": "s3", "route53": "route53", "cloudfront": "cloudfront",
    "elbv2": "elbv2", "waf": "waf", "wafv2": "wafv2",
}

_READ = re.compile(r"^(describe_|list_|get_|batch_get_)")
_NOT_AN_API = {"get_paginator", "get_waiter", "get_caller_identity"}


@dataclass
class ServiceScan:
    global_service: bool = False
    explicit_clients: set[str] = field(default_factory=set)
    calls: set[str] = field(default_factory=set)
    paginators: set[str] = field(default_factory=set)
    non_read: set[str] = field(default_factory=set)


def scan_service_file(path: Path) -> ServiceScan:
    scan = ServiceScan()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        name = node.func.attr
        first = node.args[0] if node.args else None
        if name == "__init__":
            for kw in node.keywords:
                if kw.arg == "global_service" and getattr(kw.value, "value", None) is True:
                    scan.global_service = True
        elif name == "get_paginator" and isinstance(first, ast.Constant):
            scan.paginators.add(first.value)
        elif name == "client" and isinstance(first, ast.Constant) and isinstance(first.value, str):
            scan.explicit_clients.add(first.value)
        elif name not in _NOT_AN_API and "client" in ast.unparse(node.func.value).lower():
            if _READ.match(name) or name in ALLOWED_EXACT:
                scan.calls.add(name)
            elif name in OPT_IN_ONLY:
                scan.non_read.add(name)
    return scan


def _tier(service: str, rule_count: int) -> int:
    if service in TIER1:
        return 1
    return 2 if rule_count >= 5 else 3


def _resolve_client(api: str, primary: str, extra: set[str]) -> tuple[str | None, bool]:
    """Find the boto3 client owning ``api``. Returns ``(client, ambiguous)``."""
    for c in [primary, *sorted(extra)]:
        if c in botomodel.available_clients() and api in botomodel.operations(c):
            return c, False
    owners = [c for c in botomodel.available_clients() if api in botomodel.operations(c)]
    if len(owners) == 1:
        return owners[0], False
    return None, bool(owners)


def _singular(word: str) -> str:
    if word.endswith("ies"):
        return word[:-3] + "y"
    if word.endswith("ses") or word.endswith("xes"):
        return word[:-2]
    return word[:-1] if word.endswith("s") and not word.endswith("ss") else word


def _resource_type(api: str) -> str:
    return _singular(re.sub(r"^(describe_|list_|get_|batch_get_)", "", api))


def _guess_id_field(members: list[str]) -> str | None:
    for suffix in ("Id", "Name", "Arn"):
        for m in members:
            if m.endswith(suffix):
                return m
    return None


def _build_api(client: str, svc_client: str, api: str, apis_by_client: dict[str, set[str]]) -> ApiSpec:
    spec = ApiSpec(api=api, client=client if client != svc_client else None)
    spec.paginate = botomodel.can_paginate(client, api)
    spec.resource_type = _resource_type(api)
    if api in OPT_IN_ONLY:
        spec.opt_in_flag = f"--collect-{api.replace('_', '-')}"

    list_member = botomodel.output_list_member(client, api)
    spec.result_path = botomodel.paginator_result_key(client, api) or (list_member[0] if list_member else None)
    if list_member:
        spec.id_field = _guess_id_field(list_member[1])

    required = botomodel.required_params(client, api)
    if required:
        parent = _find_parent(client, api, required, apis_by_client.get(client, set()))
        if parent:
            spec.depends_on = DependsOn(api=parent, params={p: p for p in required})
        else:
            spec.needs_review = True
            spec.note = f"required params without a parent API: {', '.join(required)}"
    elif list_member is None and spec.result_path is None and api.startswith(("list_", "describe_")):
        spec.needs_review = True
        spec.note = "could not determine result_path"
    return spec


def _find_parent(client: str, api: str, required: list[str], siblings: set[str]) -> str | None:
    for cand in sorted(siblings):
        if cand == api or botomodel.required_params(client, cand):
            continue
        member = botomodel.output_list_member(client, cand)
        if member and all(p in member[1] for p in required):
            return cand
    return None


def build_spec(prowler_services: Path, rules_master: Path, prowler_version: str | None = None) -> tuple[CollectSpec, dict]:
    rules = json.loads(rules_master.read_text(encoding="utf-8"))
    rule_count: dict[str, int] = defaultdict(int)
    for r in rules:
        rule_count[r["service"]] += 1

    report: dict = {"unresolved_apis": {}, "ambiguous_apis": {}, "services_without_client": [], "rules_without_service_dir": []}
    digest = hashlib.sha256(rules_master.read_bytes())
    services: list[ServiceSpec] = []

    service_dirs = {p.parent.name: p for p in sorted(prowler_services.glob("*/*_service.py"))}
    for name, path in service_dirs.items():
        digest.update(path.read_bytes())
        scan = scan_service_file(path)
        svc_client = CLIENT_NAMES.get(name, name)
        if svc_client not in botomodel.available_clients():
            report["services_without_client"].append(name)
            continue

        extra = {c for c in scan.explicit_clients | EXTRA_CLIENTS.get(name, set()) if c in botomodel.available_clients()}
        resolved: dict[str, set[str]] = defaultdict(set)
        for api in sorted(scan.calls | {p for p in scan.paginators if isinstance(p, str)}):
            client, ambiguous = _resolve_client(api, svc_client, extra)
            if client is None:
                (report["ambiguous_apis"] if ambiguous else report["unresolved_apis"]).setdefault(name, []).append(api)
                continue
            resolved[client].add(api)

        api_specs = [
            _build_api(client, svc_client, api, resolved)
            for client in sorted(resolved, key=lambda c: (c != svc_client, c))
            for api in sorted(resolved[client])
        ]
        for api in sorted(scan.non_read):
            client, _ = _resolve_client(api, svc_client, extra)
            if client:
                api_specs.append(_build_api(client, svc_client, api, resolved))

        scope = "global" if (scan.global_service or name in GLOBAL_SERVICES) else "regional"
        services.append(
            ServiceSpec(
                service=name,
                client=svc_client,
                scope=scope,
                tier=_tier(name, rule_count.get(name, 0)),
                collector=CUSTOM_COLLECTORS.get(name, "generic"),
                rule_count=rule_count.get(name, 0),
                apis=api_specs,
            )
        )

    report["rules_without_service_dir"] = sorted(set(rule_count) - set(service_dirs))
    source_hash = digest.hexdigest()
    spec = CollectSpec(
        spec_version=f"{date.today():%Y.%m.%d}-{source_hash[:8]}",
        prowler_version=prowler_version,
        source_hash=source_hash,
        services=services,
    )
    return spec, report


def read_prowler_version(prowler_root: Path) -> str | None:
    cfg = prowler_root / "prowler" / "config" / "config.py"
    if not cfg.exists():
        return None
    m = re.search(r'prowler_version\s*=\s*"([^"]+)"', cfg.read_text(encoding="utf-8"))
    return m.group(1) if m else None
