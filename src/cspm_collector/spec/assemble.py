"""Merge the generated spec with hand-curated per-service overrides.

Generated services without an override stay in the spec but are disabled: their dependent
calls are only guesses until someone reviews them.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from .schema import CollectSpec, ServiceSpec


def load_overrides(directory: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        out[data["service"]] = data
    return out


def assemble(generated: CollectSpec, overrides: dict[str, dict]) -> CollectSpec:
    remaining = dict(overrides)
    services: list[ServiceSpec] = []
    for svc in generated.services:
        raw = remaining.pop(svc.service, None)
        if raw is None:
            services.append(svc.model_copy(update={"enabled": False}))
            continue
        merged = {"tier": svc.tier, "rule_count": svc.rule_count, **raw}  # keep generated metadata
        services.append(ServiceSpec.model_validate(merged))
    services += [ServiceSpec.model_validate(raw) for raw in remaining.values()]  # services Prowler never calls
    return generated.model_copy(update={"services": services})
