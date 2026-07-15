"""Canonical-JSON-safe coercion for untrusted import data."""

from __future__ import annotations

import math
from typing import Any


def json_safe(value: Any, _seen: set[int] | None = None, _depth: int = 0) -> Any:
    """Make a value canonical-JSON-safe, preserving large integers as strings."""
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value if abs(value) <= 9_007_199_254_740_991 else str(value)
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
                return {str(key): json_safe(item, seen, _depth + 1) for key, item in value.items()}
            return [json_safe(item, seen, _depth + 1) for item in value]
        finally:
            seen.remove(identity)
    return str(value)
