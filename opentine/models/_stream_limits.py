"""Aggregate memory limits shared by streamed provider parsers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

MAX_STREAM_CHARS = 1024 * 1024


def _fits(value: Any, remaining: int, depth: int = 0) -> int:
    if remaining < 0 or depth > 32:
        return -1
    if value is None or isinstance(value, (bool, int, float)):
        return remaining - 32
    if isinstance(value, (str, bytes, bytearray)):
        return remaining - len(value)
    if isinstance(value, Mapping):
        if len(value) > 4096:
            return -1
        remaining -= 64
        if remaining < 0:
            return -1
        for key, item in value.items():
            remaining = _fits(key, remaining, depth + 1)
            remaining = _fits(item, remaining, depth + 1)
            if remaining < 0:
                return -1
        return remaining
    if isinstance(value, Sequence):
        if len(value) > 4096:
            return -1
        remaining -= 64
        if remaining < 0:
            return -1
        for item in value:
            remaining = _fits(item, remaining, depth + 1)
            if remaining < 0:
                return -1
        return remaining
    return -1


class SizeBudget:
    """Bound the aggregate retained size of structured provider values."""

    def __init__(self, limit: int | None = None) -> None:
        self.remaining = MAX_STREAM_CHARS if limit is None else limit

    def keep(self, value: Any, warnings: list[str], label: str) -> Any:
        remaining = _fits(value, self.remaining)
        if remaining >= 0:
            self.remaining = remaining
            return value
        warnings.append(f"streamed {label} exceeded its aggregate safe size and was discarded")
        return {"_truncated": True}
