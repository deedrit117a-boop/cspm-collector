"""Offline lookups against botocore's bundled service models (no AWS calls)."""
from __future__ import annotations

from functools import lru_cache

import botocore.session
from botocore import xform_name


@lru_cache(maxsize=1)
def _session() -> botocore.session.Session:
    return botocore.session.get_session()


@lru_cache(maxsize=1)
def available_clients() -> frozenset[str]:
    return frozenset(_session().get_available_services())


@lru_cache(maxsize=None)
def _model(client: str):
    return _session().get_service_model(client)


@lru_cache(maxsize=None)
def operations(client: str) -> frozenset[str]:
    """Snake-case operation names, e.g. ``describe_instances``."""
    return frozenset(xform_name(op) for op in _model(client).operation_names)


@lru_cache(maxsize=None)
def _paginators(client: str) -> dict:
    try:
        cfg = _session().get_paginator_model(client)._paginator_config
    except Exception:  # service has no paginators.json
        return {}
    return {xform_name(op): conf for op, conf in cfg.items()}


def can_paginate(client: str, api: str) -> bool:
    return api in _paginators(client)


def paginator_result_key(client: str, api: str) -> str | None:
    key = _paginators(client).get(api, {}).get("result_key")
    if isinstance(key, list):
        key = key[0] if key else None
    return key


def required_params(client: str, api: str) -> list[str]:
    op = _model(client).operation_model(_op_name(client, api))
    shape = op.input_shape
    return list(shape.required_members) if shape is not None else []


def input_members(client: str, api: str) -> set[str]:
    shape = _model(client).operation_model(_op_name(client, api)).input_shape
    return set(shape.members) if shape is not None else set()


def output_list_member(client: str, api: str) -> tuple[str, list[str]] | None:
    """If the response has exactly one list-of-structures member, return
    ``(member_name, item_member_names)``."""
    op = _model(client).operation_model(_op_name(client, api))
    out = op.output_shape
    if out is None:
        return None
    found = [
        (name, shape)
        for name, shape in out.members.items()
        if shape.type_name == "list" and shape.member.type_name == "structure"
    ]
    if len(found) != 1:
        return None
    name, shape = found[0]
    return name, list(shape.member.members)


def output_members(client: str, api: str) -> list[str]:
    out = _model(client).operation_model(_op_name(client, api)).output_shape
    return list(out.members) if out is not None else []


def _op_name(client: str, api: str) -> str:
    for op in _model(client).operation_names:
        if xform_name(op) == api:
            return op
    raise KeyError(f"{client}.{api}")


def item_shape(client: str, api: str, path: str):
    """The shape of one item reached by ``result_path`` (``A``, ``A.B``, ``A[].B``): lists are unwrapped.
    Returns ``None`` when the path does not exist in the API's output."""
    shape = _model(client).operation_model(_op_name(client, api)).output_shape
    for part in path.split("."):
        name = part[:-2] if part.endswith("[]") else part
        members = getattr(shape, "members", None)
        if not members or name not in members:
            return None
        shape = members[name]
        if shape.type_name == "list":
            shape = shape.member
    return shape


def shape_fields(shape) -> set[str] | None:
    """Member names of a structure shape; ``None`` for scalars/maps (not checkable)."""
    return set(shape.members) if shape is not None and shape.type_name == "structure" else None


def operation_name(client: str, api: str) -> str:
    """The service's own (PascalCase) operation name, e.g. ``DescribeDBInstances``: also the IAM action name."""
    return _op_name(client, api)
