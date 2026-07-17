"""Bounded traversal for protobuf-JSON OTLP AnyValue records."""

from __future__ import annotations

from typing import Any

_MAX_DEPTH = 100
_MAX_SAFE_INTEGER = (1 << 53) - 1


def attributes(span: dict[str, Any]) -> dict[str, Any]:
    raw = span.get("attributes") or {}
    if isinstance(raw, list):
        return {
            _key(item["key"]): any_value(item.get("value"))
            for item in raw
            if isinstance(item, dict) and item.get("key") is not None
        }
    if not isinstance(raw, dict):
        return {}
    return {_key(key): any_value(value) for key, value in raw.items()}


def any_value(value: Any) -> Any:
    """Unwrap an OTLP ``AnyValue`` with explicit cycle and depth bounds."""
    return _any_value(value, 0, set())


def _any_value(value: Any, depth: int, active: set[int]) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("OTLP AnyValue exceeds maximum nesting depth")
    if not isinstance(value, (dict, list, tuple)):
        return value
    identity = id(value)
    if identity in active:
        raise ValueError("OTLP AnyValue contains a cyclic container")
    active.add(identity)
    try:
        if isinstance(value, (list, tuple)):
            return [_any_value(item, depth + 1, active) for item in value]
        return _any_value_dict(value, depth, active)
    finally:
        active.remove(identity)


def _any_value_dict(value: dict[str, Any], depth: int, active: set[int]) -> Any:
    for name in ("stringValue", "string_value", "bytesValue", "bytes_value"):
        if name in value:
            return str(_scalar(value[name]))
    for name in ("intValue", "int_value"):
        if name in value:
            raw = _scalar(value[name])
            try:
                number = int(raw or 0)
            except (TypeError, ValueError, OverflowError):
                number = 0
            return number if abs(number) <= _MAX_SAFE_INTEGER else str(raw)
    for name in ("doubleValue", "double_value"):
        if name in value:
            return _scalar(value[name])
    for name in ("boolValue", "bool_value"):
        if name in value:
            raw = _scalar(value[name])
            return raw if isinstance(raw, bool) else str(raw).casefold() == "true"
    array = value.get("arrayValue", value.get("array_value"))
    if isinstance(array, dict):
        values = array.get("values")
        return (
            [_any_value(item, depth + 1, active) for item in values]
            if isinstance(values, list)
            else []
        )
    pairs = value.get("kvlistValue", value.get("kvlist_value"))
    if isinstance(pairs, dict) and isinstance(pairs.get("values"), list):
        return {
            _key(item["key"]): _any_value(item.get("value"), depth + 1, active)
            for item in pairs["values"]
            if isinstance(item, dict) and item.get("key") is not None
        }
    return {_key(key): _any_value(item, depth + 1, active) for key, item in value.items()}


def _scalar(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple)):
        raise ValueError("OTLP AnyValue scalar contains a container")
    return value


def _key(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        raise ValueError("OTLP AnyValue key contains a container")
    return str(value)
