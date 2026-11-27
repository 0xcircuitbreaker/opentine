"""Column values for ``tine query`` rows: a JSON value kept only when it has the column's type.

A leaf module, so every ``_query_*`` row builder can share these without importing
:mod:`opentine._query_rows` (which imports their column lists).
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any


def text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def number(value: Any) -> float | None:
    """A JSON number, or a decimal string, as a float; ``None`` for a bool or anything else."""
    if isinstance(value, int | float):
        return None if isinstance(value, bool) else float(value)
    try:
        return float(Decimal(str(value))) if isinstance(value, str) else None
    except (InvalidOperation, ValueError):
        return None


def integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def flag(value: Any) -> int | None:
    return int(value) if isinstance(value, bool) else None


__all__ = ["flag", "integer", "number", "text"]
