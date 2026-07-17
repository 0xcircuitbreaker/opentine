"""Strict, bounded parsing for provider-supplied tool arguments."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from opentine.kernel import KernelError, canonical_json
from opentine.models._stream_limits import SizeBudget

_MAX_SAFE_INTEGER = (1 << 53) - 1


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError("invalid JSON integer") from exc
    if abs(parsed) > _MAX_SAFE_INTEGER:
        raise ValueError("JSON integer exceeds the canonical safe range")
    return parsed


def _constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def strict_tool_arguments(raw: Any) -> dict[str, Any]:
    try:
        if isinstance(raw, str):
            parsed = json.loads(
                raw,
                object_pairs_hook=_pairs,
                parse_constant=_constant,
                parse_int=_integer,
            )
        elif isinstance(raw, Mapping):
            parsed = dict(raw)
        else:
            raise ValueError("tool arguments must be a JSON object")
        if not isinstance(parsed, dict):
            raise ValueError("tool arguments must be a JSON object")
        canonical_json(parsed)
        return parsed
    except (KernelError, RecursionError, TypeError) as exc:
        raise ValueError("tool arguments are not canonical JSON") from exc


def bounded_tool_arguments(
    raw: Any, budget: Any, warnings: list[str], provider: str, name: Any
) -> dict[str, Any]:
    kept = budget.keep(raw, warnings, f"{provider} tool arguments")
    if isinstance(kept, dict) and kept.get("_truncated") is True:
        return kept
    try:
        return strict_tool_arguments(kept)
    except ValueError:
        warnings.append(f"invalid JSON arguments for {str(name)[:4096]}")
        return {"_truncated": True}


def stored_tool_calls(raw: Any, budget: SizeBudget | None = None) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) > 256:
        raise ValueError("stored tool calls exceed the safe count")
    budget = budget or SizeBudget()
    result: list[dict[str, Any]] = []
    for call in raw:
        if not isinstance(call, dict):
            raise ValueError("stored tool call is malformed")
        name = call.get("name")
        call_id = call.get("id") or name
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 4096
            or not isinstance(call_id, str)
            or len(call_id) > 4096
        ):
            raise ValueError("stored tool call identity is malformed")
        kept = budget.keep(call.get("arguments", {}), [], "stored tool arguments")
        if isinstance(kept, dict) and kept.get("_truncated") is True:
            raise ValueError("stored tool arguments exceed the safe aggregate size")
        result.append({"arguments": strict_tool_arguments(kept), "id": call_id, "name": name})
    return result
