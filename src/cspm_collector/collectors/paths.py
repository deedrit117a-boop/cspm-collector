"""Tiny path language for ``result_path``: ``Key``, ``A.B`` and ``A[].B`` (flatten a list)."""
from __future__ import annotations

from typing import Any


def _walk(node: Any, parts: list[str]) -> list:
    head, rest = parts[0], parts[1:]
    flatten = head.endswith("[]")
    value = node.get(head[:-2] if flatten else head) if isinstance(node, dict) else None
    if value is None:
        return []
    if not rest:
        return list(value) if isinstance(value, list) else [value]
    if isinstance(value, list):
        out: list = []
        for v in value:
            out.extend(_walk(v, rest))
        return out
    return _walk(value, rest)


def extract(pages: list[dict], path: str) -> list:
    items: list = []
    for page in pages:
        items.extend(_walk(page, path.split(".")))
    return items


def merge_pages(pages: list[dict]) -> dict:
    """Fold paginated responses into one response: lists are concatenated, other keys keep the first value."""
    merged: dict = {}
    for page in pages:
        for key, value in page.items():
            if isinstance(value, list):
                merged.setdefault(key, []).extend(value)
            else:
                merged.setdefault(key, value)
    return merged
