"""Bounded normalization for list-shaped compatible chat content."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

MAX_BLOCKS = 1024
MAX_CHARS = 1024 * 1024


def _value(item: Any, key: str, default: Any = None) -> Any:
    return item.get(key, default) if isinstance(item, Mapping) else getattr(item, key, default)


def _clip(value: Any, remaining: int) -> tuple[str, int, bool]:
    text = value if isinstance(value, str) else ""
    kept = text[:remaining]
    return kept, remaining - len(kept), len(text) > len(kept)


def parse_chat_blocks(
    raw: Any,
) -> tuple[str, str, list[dict[str, Any]] | None, list[str]]:
    if isinstance(raw, str):
        return raw, "", None, []
    if not isinstance(raw, Sequence) or isinstance(raw, (bytes, bytearray)):
        return "", "", None, []
    text_parts: list[str] = []
    reasoning_parts: list[str] = []
    normalized: list[dict[str, Any]] = []
    warnings: list[str] = []
    remaining = MAX_CHARS
    retained = 0
    truncated = False
    for block in raw:
        if retained >= MAX_BLOCKS:
            truncated = True
            break
        retained += 1
        block_type = _value(block, "type")
        if block_type == "text":
            part, remaining, cut = _clip(_value(block, "text", ""), remaining)
            text_parts.append(part)
            normalized.append({"type": "text", "text": part})
            if cut:
                warnings.append("Chat content blocks truncated at 1048576 characters")
        elif block_type in {"thinking", "reasoning"}:
            nested = _value(block, "thinking", _value(block, "reasoning", [])) or []
            nested = [nested] if isinstance(nested, str) else nested
            if not isinstance(nested, Sequence) or isinstance(nested, (bytes, bytearray)):
                nested = []
            kept: list[dict[str, str]] = []
            for item in nested:
                if retained >= MAX_BLOCKS:
                    truncated = True
                    break
                retained += 1
                value = item if isinstance(item, str) else _value(item, "text", "")
                part, remaining, cut = _clip(value, remaining)
                reasoning_parts.append(part)
                kept.append({"type": "text", "text": part})
                if cut:
                    warnings.append("Chat content blocks truncated at 1048576 characters")
            normalized.append({"type": "thinking", "thinking": kept})
    if truncated:
        warnings.append(f"Chat content blocks truncated at {MAX_BLOCKS} blocks")
    return "".join(text_parts), "".join(reasoning_parts), normalized, warnings


def count_chat_blocks(records: Sequence[dict[str, Any]]) -> int:
    """Count normalized outer and nested blocks against one aggregate ceiling."""
    total = 0
    for record in records:
        total += 1
        if record.get("type") == "thinking":
            nested = record.get("thinking", [])
            total += len(nested) if isinstance(nested, list) else 0
    return total
