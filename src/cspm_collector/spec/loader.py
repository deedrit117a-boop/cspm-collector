"""Load and validate ``collect_spec.yaml``."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from cspm_collector.collectors.masking import parse_rule

from . import botomodel
from .readonly import check_api_name
from .schema import ApiSpec, CollectSpec, ServiceSpec


@dataclass(frozen=True)
class Issue:
    level: str  # "error" | "warning"
    where: str
    message: str


def load_spec(path: str | Path) -> CollectSpec:
    with open(path, encoding="utf-8") as f:
        return CollectSpec.model_validate(yaml.safe_load(f))


def dump_spec(spec: CollectSpec, path: str | Path) -> None:
    data = spec.model_dump(mode="json", exclude_none=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True, width=120)


def _param_name(name: str) -> str:
    """``Ids[]`` in depends_on.params means "wrap the value in a list" for the real parameter ``Ids``."""
    return name[:-2] if name.endswith("[]") else name


def _check_params(svc: ServiceSpec, a: ApiSpec, client: str, where: str) -> list[Issue]:
    """Disabled services come from the unreviewed generated draft, so their problems are only warnings."""
    level = "error" if svc.enabled else "warning"
    issues: list[Issue] = []
    provided = set(a.parameters) | {_param_name(p) for p in (a.depends_on.params if a.depends_on else {})}
    required = set(botomodel.required_params(client, a.api))
    known = botomodel.input_members(client, a.api)
    if required - provided:
        issues.append(Issue(level, where, f"missing required parameters: {', '.join(sorted(required - provided))}"))
    unknown = provided - known
    if unknown:
        issues.append(Issue(level, where, f"unknown parameters: {', '.join(sorted(unknown))}"))
    return issues


def _item_fields(svc: ServiceSpec, a: ApiSpec) -> tuple[set[str] | None, bool, str | None]:
    """``(fields of one item, item is a scalar, problem)`` for the items an API produces."""
    client = a.client or svc.client
    if a.result_path:
        shape = botomodel.item_shape(client, a.api, a.result_path)
        if shape is None:
            return None, False, f"result_path '{a.result_path}' is not in the output of {client}.{a.api}"
        fields = botomodel.shape_fields(shape)
        return fields, fields is None and shape.type_name in ("string", "integer", "long"), None
    return set(botomodel.output_members(client, a.api)), False, None


def _check_shapes(svc: ServiceSpec, a: ApiSpec, by_key: dict[str, ApiSpec], where: str) -> list[Issue]:
    """Typos in result_path / id_field / arn_field / depends_on fields would silently produce wrong or empty
    resources, so every field name is checked against botocore's output shapes."""
    level = "error" if svc.enabled else "warning"
    issues: list[Issue] = []
    fields, scalar, problem = _item_fields(svc, a)
    if problem:
        return [Issue(level, where, problem)]
    if a.result_path:
        for ident in (a.id_field or "").split("+") if a.id_field else []:
            if scalar and ident != "Value":
                issues.append(Issue(level, where, f"items are scalars: id_field must be 'Value', not '{ident}'"))
            elif fields is not None and ident not in fields:
                issues.append(Issue(level, where, f"id_field '{ident}' is not a member of the item"))
        if a.arn_field and fields is not None and a.arn_field not in fields:
            issues.append(Issue(level, where, f"arn_field '{a.arn_field}' is not a member of the item"))

    parent = by_key.get(a.depends_on.api) if a.depends_on else None
    if parent is not None:
        pfields, pscalar, pproblem = _item_fields(svc, parent)
        wanted = list(a.depends_on.params.values()) + list(a.inherit.values())
        for name in wanted:
            if pscalar and name != "Value":
                issues.append(Issue(level, where, f"parent '{parent.key}' yields scalars: use 'Value', not '{name}'"))
            elif pfields is not None and name not in pfields:
                issues.append(Issue(level, where, f"'{name}' is not a member of {parent.key}'s items"))
    return issues


def validate_spec(spec: CollectSpec, check_boto: bool = True) -> list[Issue]:
    """Structural, read-only and (optionally) botocore-model checks."""
    issues: list[Issue] = []
    seen: set[str] = set()
    clients = botomodel.available_clients() if check_boto else frozenset()

    for svc in spec.services:
        if svc.service in seen:
            issues.append(Issue("error", svc.service, "duplicate service"))
        seen.add(svc.service)
        if check_boto and svc.client not in clients:
            issues.append(Issue("error", svc.service, f"unknown boto3 client '{svc.client}'"))

        keys: dict[str, int] = {}
        for a in svc.apis:
            keys[a.key] = keys.get(a.key, 0) + 1
        for key, n in keys.items():
            if n > 1:
                issues.append(Issue("error", f"{svc.service}.{key}", "duplicate API key; give the second call an alias"))
        if svc.enablement_api and svc.enablement_api not in keys:
            issues.append(Issue("error", svc.service, f"enablement_api '{svc.enablement_api}' not in service"))

        for a in svc.apis:
            where = f"{svc.service}.{a.key}"
            verdict = check_api_name(a.api, a.opt_in_flag)
            if verdict:
                issues.append(Issue(verdict[0], where, verdict[1]))

            client = a.client or svc.client
            if check_boto:
                if client not in clients:
                    issues.append(Issue("error", where, f"unknown boto3 client '{client}'"))
                elif a.api not in botomodel.operations(client):
                    issues.append(Issue("error", where, f"{client} has no operation {a.api}"))
                else:
                    if a.paginate and not botomodel.can_paginate(client, a.api):
                        issues.append(Issue("warning", where, "paginate=true but no botocore paginator"))
                    issues += _check_params(svc, a, client, where)
                    issues += _check_shapes(svc, a, {x.key: x for x in svc.apis}, where)

            for rule in a.mask:
                try:
                    parse_rule(rule)
                except ValueError as exc:
                    issues.append(Issue("error", where, str(exc)))
            if a.as_resource and not (a.depends_on and a.result_path and a.resource_type):
                issues.append(Issue("error", where, "as_resource needs depends_on, result_path and resource_type"))
            if a.depends_on and a.depends_on.api not in keys:
                issues.append(Issue("error", where, f"depends_on '{a.depends_on.api}' not in service"))
            if a.depends_on and a.depends_on.api == a.key:
                issues.append(Issue("error", where, "depends_on refers to itself"))
    return issues
