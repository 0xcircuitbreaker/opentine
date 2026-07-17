"""Bounded opaque continuation records for provider-managed tool turns."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Iterable
from typing import Any

from opentine.kernel import KernelError, canonical_json
from opentine.models._stream_limits import SizeBudget
from opentine.models._usage import value

MAX_PROVIDER_PARTS = 1024


def _keep(record: dict[str, Any], budget: SizeBudget, warnings: list[str], label: str):
    try:
        canonical_json(record)
    except (KernelError, RecursionError):
        warnings.append(f"{label} contained non-canonical data and was discarded")
        return None
    kept = budget.keep(record, warnings, label)
    return kept if isinstance(kept, dict) and not kept.get("_truncated") else None


def anthropic_blocks(raw: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Retain the exact signed thinking/tool fields Anthropic requires on replay."""
    records: list[dict[str, Any]] = []
    budget = SizeBudget()
    for index, block in enumerate(raw or []):
        if index >= MAX_PROVIDER_PARTS:
            warnings.append(f"Anthropic continuation truncated at {MAX_PROVIDER_PARTS} blocks")
            break
        kind = value(block, "type")
        if kind == "thinking":
            record = {
                "type": "thinking",
                "thinking": value(block, "thinking", ""),
                "signature": value(block, "signature", ""),
            }
        elif kind == "redacted_thinking":
            record = {"type": kind, "data": value(block, "data", "")}
        elif kind == "text":
            record = {"type": kind, "text": value(block, "text", "")}
        elif kind == "tool_use":
            record = {
                "type": kind,
                "id": value(block, "id"),
                "name": value(block, "name"),
                "input": value(block, "input", {}),
            }
        else:
            continue
        if kept := _keep(record, budget, warnings, "Anthropic continuation"):
            records.append(kept)
    return records


def anthropic_sdk_blocks(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate stored Anthropic blocks before returning them to the SDK."""
    allowed = {
        "thinking": ("thinking", "signature"),
        "redacted_thinking": ("data",),
        "text": ("text",),
        "tool_use": ("id", "name", "input"),
    }
    result: list[dict[str, Any]] = []
    budget = SizeBudget()
    for index, record in enumerate(records):
        if index >= MAX_PROVIDER_PARTS:
            raise ValueError("stored Anthropic continuation exceeds safe block count")
        if not isinstance(record, dict) or record.get("type") not in allowed:
            raise ValueError("invalid stored Anthropic continuation block")
        try:
            canonical_json(record)
        except (KernelError, RecursionError) as exc:
            raise ValueError("stored Anthropic continuation is not canonical JSON") from exc
        kept = budget.keep(record, [], "Anthropic continuation")
        if not isinstance(kept, dict) or kept.get("_truncated"):
            raise ValueError("stored Anthropic continuation exceeds safe aggregate size")
        kind = record["type"]
        result.append({"type": kind, **{key: record.get(key) for key in allowed[kind]}})
    return result


def google_part(part: Any) -> dict[str, Any] | None:
    """Normalize one Gemini part, encoding its opaque signature losslessly."""
    record: dict[str, Any] = {}
    text = value(part, "text")
    if isinstance(text, str):
        record["text"] = text
    thought = value(part, "thought")
    if isinstance(thought, bool):
        record["thought"] = thought
    signature = value(part, "thought_signature")
    if isinstance(signature, (bytes, bytearray)):
        record["thought_signature"] = base64.b64encode(bytes(signature)).decode("ascii")
    elif isinstance(signature, str):
        record["thought_signature"] = signature
    function = value(part, "function_call")
    if function:
        record["function_call"] = {
            "id": value(function, "id"),
            "name": value(function, "name"),
            "args": value(function, "args", {}),
        }
    return record or None


def google_blocks(raw: Any, warnings: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    budget = SizeBudget()
    for index, part in enumerate(raw or []):
        if index >= MAX_PROVIDER_PARTS:
            warnings.append(f"Google continuation truncated at {MAX_PROVIDER_PARTS} parts")
            break
        record = google_part(part)
        if record and (kept := _keep(record, budget, warnings, "Google continuation")):
            records.append(kept)
    return records


def google_sdk_parts(types: Any, records: Iterable[dict[str, Any]]) -> list[Any]:
    """Rebuild Gemini SDK parts with exact call IDs and thought signatures."""
    parts: list[Any] = []
    budget = SizeBudget()
    for index, record in enumerate(records):
        if index >= MAX_PROVIDER_PARTS:
            raise ValueError("stored Google continuation exceeds safe part count")
        if not isinstance(record, dict):
            raise ValueError("invalid stored Google continuation part")
        try:
            canonical_json(record)
        except (KernelError, RecursionError) as exc:
            raise ValueError("stored Google continuation is not canonical JSON") from exc
        kept = budget.keep(record, [], "Google continuation")
        if not isinstance(kept, dict) or kept.get("_truncated"):
            raise ValueError("stored Google continuation exceeds safe aggregate size")
        kwargs: dict[str, Any] = {}
        for name in ("text", "thought"):
            if name in record:
                kwargs[name] = record[name]
        signature = record.get("thought_signature")
        if signature is not None:
            try:
                kwargs["thought_signature"] = base64.b64decode(signature, validate=True)
            except (binascii.Error, ValueError, TypeError):
                raise ValueError("invalid stored Google thought signature") from None
        function = record.get("function_call")
        if function:
            kwargs["function_call"] = types.FunctionCall(
                id=function.get("id"),
                name=function.get("name"),
                args=function.get("args", {}),
            )
        parts.append(types.Part(**kwargs))
    return parts
