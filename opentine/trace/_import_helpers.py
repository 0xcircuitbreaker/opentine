"""Defensive coercion and OTLP/JSON traversal for trace importers."""

from __future__ import annotations

import math
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any


def first(source: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        value = source.get(name)
        if value not in (None, ""):
            return value
    return default


def integer(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def dictionary(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def mapping(value: Any) -> dict[str, Any]:
    """Coerce payloads without corrupting ordinary list-shaped chat messages."""
    if isinstance(value, dict):
        return value
    if value in (None, ""):
        return {}
    return {"messages": value} if isinstance(value, list) else {"value": value}


def timestamp(value: Any) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        result = float(value)
        return result if math.isfinite(result) else 0.0
    if isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            result = float(text)
            return result if math.isfinite(result) else 0.0
        except ValueError:
            pass
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.timestamp()
        except (OverflowError, ValueError):
            return 0.0
    return 0.0


def any_value(value: Any) -> Any:
    """Unwrap a protobuf-JSON OTLP ``AnyValue`` without throwing on odd shapes."""
    if not isinstance(value, dict):
        return value
    for name in ("stringValue", "string_value"):
        if name in value:
            return str(value[name])
    for name in ("intValue", "int_value"):
        if name in value:
            number = integer(value[name])
            return number if abs(number) <= 9_007_199_254_740_991 else str(value[name])
    for name in ("doubleValue", "double_value"):
        if name in value:
            return value[name]
    for name in ("boolValue", "bool_value"):
        if name in value:
            raw = value[name]
            return raw if isinstance(raw, bool) else str(raw).casefold() == "true"
    for name in ("bytesValue", "bytes_value"):
        if name in value:
            return str(value[name])
    array = first(value, "arrayValue", "array_value")
    if isinstance(array, dict):
        values = array.get("values")
        return [any_value(item) for item in values] if isinstance(values, list) else []
    pairs = first(value, "kvlistValue", "kvlist_value")
    if isinstance(pairs, dict) and isinstance(pairs.get("values"), list):
        return {
            str(item["key"]): any_value(item.get("value"))
            for item in pairs["values"]
            if isinstance(item, dict) and item.get("key") is not None
        }
    return {str(key): any_value(item) for key, item in value.items()}


def attributes(span: dict[str, Any]) -> dict[str, Any]:
    raw = span.get("attributes") or {}
    if isinstance(raw, list):
        return {
            str(item["key"]): any_value(item.get("value"))
            for item in raw
            if isinstance(item, dict) and item.get("key") is not None
        }
    return {str(key): any_value(value) for key, value in dictionary(raw).items()}


def otel_spans(source: Iterable[dict[str, Any]] | dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield spans from either an extracted span list or a complete OTLP/JSON document."""
    if isinstance(source, dict):
        resources = first(source, "resourceSpans", "resource_spans")
        if isinstance(resources, list):
            for resource in resources:
                scopes = first(dictionary(resource), "scopeSpans", "scope_spans", default=[])
                for scope in scopes if isinstance(scopes, list) else []:
                    spans = dictionary(scope).get("spans") or []
                    yield from (span for span in spans if isinstance(span, dict))
            return
        spans = source.get("spans")
        if isinstance(spans, list):
            yield from (span for span in spans if isinstance(span, dict))
        elif any(name in source for name in ("traceId", "trace_id", "spanId", "span_id")):
            yield source
        return
    for item in source:
        if isinstance(item, dict):
            yield from otel_spans(item)
