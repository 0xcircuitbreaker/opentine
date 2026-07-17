"""Small immutable-container helpers for trusted billing records."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any


class _FrozenList(tuple):
    """Immutable tuple with list-compatible value equality."""

    def __eq__(self, other: object) -> bool:
        return tuple(self) == tuple(other) if isinstance(other, (list, tuple)) else False

    __hash__ = tuple.__hash__


def freeze(value: Any) -> Any:
    """Defensively copy mappings/sequences into immutable containers."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenList(freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(freeze(item) for item in value)
    return value


def thaw(value: Any) -> Any:
    """Return ordinary JSON-shaped containers for public serialization."""
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value
