"""Make AWS responses BSON-safe and hash them deterministically."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any

# Full-width look-alikes used to escape characters MongoDB dislikes in field names.
_DOT = "．"
_DOLLAR = "＄"
_INT64_MAX = 2**63 - 1


def normalize(obj: Any) -> Any:
    """Convert values BSON cannot hold (or that hash unstably) into plain JSON types."""
    if isinstance(obj, dict):
        return {str(k): normalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [normalize(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted((normalize(v) for v in obj), key=repr)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() and abs(obj) <= _INT64_MAX else str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(bytes(obj)).decode("ascii")
    if isinstance(obj, bool) or obj is None or isinstance(obj, (str, float)):
        return obj
    if isinstance(obj, int):
        return obj if abs(obj) <= _INT64_MAX else str(obj)
    return str(obj)


def _is_policy(node: Any) -> bool:
    return isinstance(node, dict) and "Statement" in node and "Version" in node


def _canon_policy(node: Any) -> Any:
    """Policy documents are sets in disguise: AWS may return ``Principal.Service`` or ``Action`` arrays of scalars
    in a different order on every call. Sort those arrays; keep the order of ``Statement`` itself."""
    if isinstance(node, dict):
        return {k: _canon_policy(v) for k, v in node.items()}
    if isinstance(node, list):
        items = [_canon_policy(v) for v in node]
        if all(isinstance(v, (str, int, float, bool)) for v in items):
            return sorted(items, key=repr)
        return items
    return node


def hash_view(node: Any) -> Any:
    """What the change-detection hash is computed from. Identical to the data, except that policy documents
    (as objects or as JSON strings, e.g. SQS/SNS ``Policy``) are compared order-insensitively, so a reordered
    array does not count as a change. The stored ``config`` is never altered."""
    if isinstance(node, dict):
        return _canon_policy(node) if _is_policy(node) else {k: hash_view(v) for k, v in node.items()}
    if isinstance(node, list):
        return [hash_view(v) for v in node]
    if isinstance(node, str) and node.startswith("{") and "Statement" in node:
        try:
            parsed = json.loads(node)
        except ValueError:
            return node
        if _is_policy(parsed):
            return _canon_policy(parsed)  # same shape as the object form, so string and object compare equal
    return node


def canonical_hash(normalized: Any) -> str:
    """SHA-256 of the key-sorted JSON form of an already normalized value."""
    text = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _escape_key(key: str) -> str:
    key = key.replace(".", _DOT).replace("\x00", "＀")
    return _DOLLAR + key[1:] if key.startswith("$") else key


def _unescape_key(key: str) -> str:
    key = key.replace(_DOT, ".").replace("＀", "\x00")
    return "$" + key[1:] if key.startswith(_DOLLAR) else key


def escape_keys(obj: Any) -> tuple[Any, bool]:
    """Escape ``.`` and a leading ``$`` in every field name. Returns ``(value, changed)``."""
    changed = False

    def walk(o: Any) -> Any:
        nonlocal changed
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                nk = _escape_key(k)
                changed |= nk != k
                out[nk] = walk(v)
            return out
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o

    return walk(obj), changed


def unescape_keys(obj: Any) -> Any:
    """Inverse of :func:`escape_keys` (assumes the data never held the look-alike characters)."""
    if isinstance(obj, dict):
        return {_unescape_key(k): unescape_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [unescape_keys(v) for v in obj]
    return obj
