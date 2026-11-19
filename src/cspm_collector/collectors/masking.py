"""Spec-driven masking (``ApiSpec.mask``): secret-bearing values never reach MongoDB.

Rules are strings ``kind:path``; the path is relative to the item / detail response and may contain ``[]``
to step through lists:

* ``value:basicAuthCredentials``            replace that attribute with the mask
* ``b64:OnCreate[].Content``                like ``value`` for base64 text: decoded, scanned, then masked
* ``map:Environment``                       an object name -> value; every value is masked
* ``pairs:path|NameField|ValueField``       a list of objects such as ``[{name, value}]``; values are masked
* ``pairs:path|NameField|ValueField|F=V``   same, only for entries whose field ``F`` equals ``V``
* ``smap:`` / ``spairs:``                   the selective variants: only entries that look like secrets are masked
                                            (for settings that are mostly harmless, e.g. Glue default arguments)

Names stay readable (they say *which* variable exists); only values are replaced. Every secret-looking name or
value is reported as ``{"location", "type"[, "line"]}`` and never as content.
"""
from __future__ import annotations

import base64
import binascii
from typing import Any

from cspm_collector.core.secrets import MASK, scan_text

from .paths import extract

KINDS = {"value", "b64", "map", "pairs", "smap", "spairs"}


def parse_rule(rule: str) -> tuple[str, list[str]]:
    kind, _, rest = rule.partition(":")
    if kind not in KINDS or not rest:
        raise ValueError(f"bad mask rule '{rule}': expected value:<path>, map:<path> or pairs:<path>|<name>|<value>")
    parts = rest.split("|")
    if kind in ("pairs", "spairs") and len(parts) not in (3, 4):
        raise ValueError(f"bad mask rule '{rule}': {kind} needs path|NameField|ValueField[|Field=Value]")
    return kind, parts


def _holders(obj: Any, path: str) -> tuple[list[dict], str]:
    """The dict nodes that own the last attribute of ``path``, and that attribute's name."""
    *parents, attr = path.split(".")
    nodes = extract([obj], ".".join(parents)) if parents else [obj]
    return [n for n in nodes if isinstance(n, dict)], attr


def _decode(text: str) -> str:
    try:
        return base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return text


def _hits(text: str, location: str) -> list[dict]:
    return [{"location": location, **f} for f in scan_text(text)]


def apply_mask(obj: Any, rule: str, location: str) -> list[dict]:
    """Mask ``obj`` in place according to ``rule``; return the secret findings."""
    kind, parts = parse_rule(rule)
    path = parts[0]
    findings: list[dict] = []
    holders, attr = _holders(obj, path)
    for holder in holders:
        if attr not in holder or holder[attr] in (None, ""):
            continue
        where = f"{location}.{path}"
        value = holder[attr]
        if kind in ("value", "b64"):
            if isinstance(value, str):
                findings += _hits(_decode(value) if kind == "b64" else value, where)
            holder[attr] = MASK
        elif kind in ("map", "smap") and isinstance(value, dict):
            for name, v in value.items():
                hits = [{"location": f"{where}.{name}", "type": f["type"]} for f in scan_text(f"{name}={v}")]
                findings += hits
                if kind == "map" or hits:
                    value[name] = MASK
        elif kind in ("pairs", "spairs") and isinstance(value, list):
            name_f, value_f = parts[1], parts[2]
            flt = parts[3].split("=", 1) if len(parts) == 4 else None
            for entry in value:
                if not isinstance(entry, dict) or value_f not in entry:
                    continue
                if flt and entry.get(flt[0]) != flt[1]:
                    continue
                label = entry.get(name_f)
                hits = [{"location": f"{where}.{label}", "type": f["type"]}
                        for f in scan_text(f"{label}={entry[value_f]}")]
                findings += hits
                if kind == "pairs" or hits:
                    entry[value_f] = MASK
    return findings
