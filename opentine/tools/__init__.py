"""Built-in tools — plain functions, introspectable signatures."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

_TYPE_MAP = {str: "string", int: "integer", float: "number", bool: "boolean"}


def tool_schema(fn: Callable) -> dict[str, Any]:
    """Build a tool-use schema from a function's signature + docstring."""
    sig = inspect.signature(fn)
    props, required = {}, []
    for name, p in sig.parameters.items():
        props[name] = {"type": _TYPE_MAP.get(p.annotation, "string"), "description": name}
        if p.default is inspect.Parameter.empty:
            required.append(name)
    return {
        "name": fn.__name__,
        "description": (fn.__doc__ or "").strip(),
        "input_schema": {"type": "object", "properties": props, "required": required},
    }
