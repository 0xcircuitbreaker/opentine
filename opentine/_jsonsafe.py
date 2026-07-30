"""Canonical-JSON-safe coercion for untrusted import data."""

from __future__ import annotations

import hashlib
import math
from typing import Any


def _string(value: Any) -> str:
    try:
        return str(value)
    except ValueError:
        if isinstance(value, int):
            magnitude = abs(value)
            size = max(1, (magnitude.bit_length() + 7) // 8)
            digest = hashlib.sha256(magnitude.to_bytes(size, "big")).hexdigest()
            sign = "-" if value < 0 else "+"
            return f"[BIGINT:{sign}{magnitude.bit_length()}:{digest}]"
        return f"[UNREPRESENTABLE:{type(value).__name__}]"


def json_safe(value: Any, _seen: set[int] | None = None, _depth: int = 0) -> Any:
    """Make a value canonical-JSON-safe, preserving large integers as strings.

    ``_depth`` truncates rather than refuses on purpose: this is the *import*
    path, where untrusted trace data must land in the store instead of failing.
    Its bound is reached long before any interpreter's frame budget, and the
    recursion below is written as statements so it stays that way — a
    comprehension costs a second frame per level before 3.12 (PEP 709 inlined
    them in 3.12), which is how the same input crossed the 1000-frame limit at
    half the nesting depth on the declared support floor.
    """
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value if abs(value) <= 9_007_199_254_740_991 else _string(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, (dict, list, tuple)):
        seen = _seen if _seen is not None else set()
        identity = id(value)
        if identity in seen:
            return "[CIRCULAR]"
        if _depth >= 100:
            return "[MAX_DEPTH]"
        seen.add(identity)
        try:
            if isinstance(value, dict):
                result = {}
                for key, item in value.items():
                    name = _string(key)
                    if name in result:
                        raise ValueError(f"mapping keys collide after string conversion: {name!r}")
                    result[name] = json_safe(item, seen, _depth + 1)
                return result
            items = []
            for item in value:
                items.append(json_safe(item, seen, _depth + 1))
            return items
        finally:
            seen.remove(identity)
    return _string(value)
