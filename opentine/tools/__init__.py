"""Built-in tools — plain functions, introspectable signatures."""

from __future__ import annotations

import inspect
import types
from collections.abc import Callable
from typing import Any, Union, get_args, get_origin, get_type_hints

_TYPE_MAP = {str: "string", int: "integer", float: "number", bool: "boolean"}


def _type_schema(annotation: Any) -> dict[str, Any]:
    origin = get_origin(annotation)
    if origin in (types.UnionType, Union):
        candidates = [item for item in get_args(annotation) if item is not type(None)]
        return _type_schema(candidates[0]) if len(candidates) == 1 else {"type": "string"}
    if origin in (list, tuple, set):
        arguments = get_args(annotation)
        return {"type": "array", "items": _type_schema(arguments[0] if arguments else str)}
    if origin is dict:
        return {"type": "object"}
    return {"type": _TYPE_MAP.get(annotation, "string")}


def tool_schema(fn: Callable) -> dict[str, Any]:
    """Build a tool-use schema from a function's signature + docstring."""
    sig = inspect.signature(fn)
    try:
        hints = get_type_hints(fn)
    except (NameError, TypeError):
        hints = {}
    hidden = frozenset(getattr(fn, "__opentine_hidden_parameters__", ()))
    props, required = {}, []
    for name, p in sig.parameters.items():
        if name in hidden:
            continue
        props[name] = {**_type_schema(hints.get(name, p.annotation)), "description": name}
        if p.default is inspect.Parameter.empty:
            required.append(name)
    return {
        "name": fn.__name__,
        "description": (fn.__doc__ or "").strip(),
        "input_schema": {
            "type": "object",
            "properties": props,
            "required": required,
            "additionalProperties": False,
        },
    }
