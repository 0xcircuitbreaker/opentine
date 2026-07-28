"""Defensive coercion and OTLP/JSON traversal for trace importers."""

from __future__ import annotations

import math
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any

_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_INPUT_RECORDS = 100_000
_TOKEN_USAGE = {
    "input",
    "output",
    "cache_read",
    "cache_write_5m",
    "cache_write_1h",
    "reasoning",
    "total",
}


def logical_size(value: Any, limit: int) -> int:
    """Estimate retained JSON-safe size with bounded-depth, incremental traversal."""
    total = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal total
        if total > limit:
            return
        identity = id(item)
        if isinstance(item, str):
            total += len(item) * 4 + 32
        elif isinstance(item, (bytes, bytearray)):
            total += len(item) * 4 + 32
        elif item is None or isinstance(item, (bool, float)):
            total += 32
        elif isinstance(item, int):
            digits = item.bit_length() * 30103 // 100000 + 1
            total += max(32, digits * 4 + 8)
        elif isinstance(item, dict):
            total += 64
            if identity in active or depth >= 100:
                total += 64
            else:
                total += len(item) * 16
                active.add(identity)
                try:
                    for key, child in item.items():
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                        if total > limit:
                            break
                finally:
                    active.remove(identity)
        elif isinstance(item, (list, tuple)):
            total += 64
            if identity in active or depth >= 100:
                total += 64
            else:
                total += len(item) * 8
                active.add(identity)
                try:
                    for child in item:
                        visit(child, depth + 1)
                        if total > limit:
                            break
                finally:
                    active.remove(identity)
        else:
            raise ValueError(f"trace import contains unsupported {type(item).__name__} payload")

    visit(value, 0)
    return total


def first(source: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        value = source.get(name)
        if value not in (None, ""):
            return value
    return default


def optional_string(value: Any) -> str | None:
    return None if value is None or value == "" else str(value)


def event_kind(value: Any) -> str:
    normalized = str(value or "model").casefold()
    if normalized in {"model", "tool", "human", "policy", "approval", "subagent", "error"}:
        return normalized
    if "tool" in normalized:
        return "tool"
    return "error" if "error" in normalized or "exception" in normalized else "model"


def integer(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def dictionary(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def safe_usage(value: Any) -> tuple[dict[str, int | float], list[str]]:
    """Keep only graph-safe numeric usage, reporting discarded dimensions."""
    result: dict[str, int | float] = {}
    warnings: list[str] = []
    for name, raw in dictionary(value).items():
        valid = (type(raw) is int and raw >= 0) or (
            type(raw) is float and math.isfinite(raw) and raw >= 0
        )
        if name in _TOKEN_USAGE:
            valid = valid and (
                (type(raw) is int and raw <= _MAX_SAFE_INTEGER)
                or (type(raw) is float and raw.is_integer() and raw <= _MAX_SAFE_INTEGER)
            )
        if isinstance(name, str) and valid:
            result[name] = int(raw) if name in _TOKEN_USAGE else raw
        else:
            warnings.append(f"discarded invalid usage dimension {name!r}")
    return result, warnings


def imported_usage(value: Any, attributes: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    usage, warnings = safe_usage(value)
    if warnings:
        attributes["opentine.import_warnings"] = warnings
    return usage, attributes


def otel_usage(attributes: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    return imported_usage(
        {
            "input": attributes.get("gen_ai.usage.input_tokens", 0),
            "output": attributes.get("gen_ai.usage.output_tokens", 0),
        },
        attributes,
    )


def mapping(value: Any) -> dict[str, Any]:
    """Coerce payloads without corrupting ordinary list-shaped chat messages."""
    if isinstance(value, dict):
        return value
    if value in (None, ""):
        return {}
    return {"messages": value} if isinstance(value, list) else {"value": value}


def timestamp(value: Any) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            result = float(value)
        except OverflowError:
            return 0.0
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


def otel_spans(source: Iterable[dict[str, Any]] | dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield spans from either an extracted span list or a complete OTLP/JSON document."""

    def dictionaries(values: Iterable[Any]) -> Iterator[dict[str, Any]]:
        for index, value in enumerate(values):
            if index >= _MAX_INPUT_RECORDS:
                raise ValueError("trace import exceeds maximum input-record count")
            if isinstance(value, dict):
                yield value

    if isinstance(source, dict):
        resources = first(source, "resourceSpans", "resource_spans")
        if isinstance(resources, list):
            for resource in dictionaries(resources):
                scopes = first(dictionary(resource), "scopeSpans", "scope_spans", default=[])
                for scope in dictionaries(scopes if isinstance(scopes, list) else []):
                    spans = dictionary(scope).get("spans") or []
                    yield from dictionaries(spans if isinstance(spans, list) else [])
            return
        spans = source.get("spans")
        if isinstance(spans, list):
            yield from dictionaries(spans)
        elif any(name in source for name in ("traceId", "trace_id", "spanId", "span_id")):
            yield source
        return
    for item in dictionaries(source):
        yield from otel_spans(item)
