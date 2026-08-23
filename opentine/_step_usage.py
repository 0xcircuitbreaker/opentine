"""Per-dimension guard for a step's recorded usage counters.

Split out of :mod:`opentine._graph_types` so the value types themselves stay
small; the rule is unchanged and still spelled once, for every reader that puts
usage on a ``Step`` (the ``.tine`` loader, the v3 loader, ``add_step``).
"""

from __future__ import annotations

import math
from typing import Any

_MAX_SAFE_INTEGER = (1 << 53) - 1
_TOKEN_USAGE = {
    "input",
    "output",
    "cache_read",
    "cache_write_5m",
    "cache_write_1h",
    "reasoning",
    "total",
}


def _usage_value(name: str, value: Any) -> int | float:
    error = f"step usage.{name} must be a finite, non-negative safe number"
    if not isinstance(name, str) or not name:
        raise ValueError("step usage names must be non-empty strings")
    if isinstance(value, bool) or type(value) not in {int, float}:
        raise ValueError(error)
    if isinstance(value, int):
        if value < 0 or value > _MAX_SAFE_INTEGER:
            raise ValueError(error)
        return value
    if not math.isfinite(value) or value < 0:
        raise ValueError(error)
    if name in _TOKEN_USAGE and not value.is_integer():
        raise ValueError(f"step usage.{name} must be an integer token count")
    if value.is_integer() and value <= _MAX_SAFE_INTEGER:
        return int(value)
    if name in _TOKEN_USAGE:
        raise ValueError(error)
    return value
