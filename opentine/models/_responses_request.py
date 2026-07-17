"""Bounded request conversion for OpenAI Responses."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from opentine.models._stream_content import MAX_STREAM_BLOCKS
from opentine.models._streaming import SizeBudget
from opentine.models._tool_args import stored_tool_calls


def plain(item: Any) -> dict[str, Any]:
    if isinstance(item, Mapping):
        return dict(item)
    dump = getattr(item, "model_dump", None)
    if callable(dump):
        return dump(exclude_none=True)
    try:
        return {
            name: raw
            for name, raw in vars(item).items()
            if not name.startswith("_") and raw is not None
        }
    except TypeError:
        raise ValueError("invalid stored Responses continuation item") from None


def response_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    if not tools:
        return None
    return [
        {
            "type": "function",
            "name": tool["name"],
            "description": tool["description"],
            "parameters": tool["input_schema"],
            "strict": bool(tool.get("strict", False)),
        }
        for tool in tools
    ]


def _preserved(raw: Any, budget: SizeBudget) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError("stored Responses continuation must be a list")
    if len(raw) > MAX_STREAM_BLOCKS:
        raise ValueError("stored Responses continuation exceeds safe block count")
    converted: list[dict[str, Any]] = []
    for raw_item in raw:
        item = plain(raw_item)
        warnings: list[str] = []
        kept = budget.keep(item, warnings, "Responses continuation")
        if not isinstance(kept, dict) or kept.get("_truncated"):
            raise ValueError("stored Responses continuation exceeds safe aggregate size")
        converted.append(kept)
    return converted


def response_input(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    budget = SizeBudget()
    for message in messages:
        preserved = message.get("response_items")
        if preserved:
            converted = _preserved(preserved, budget)
            has_message = any(item.get("type") == "message" for item in converted)
            if message.get("content") and not has_message:
                items.append({"role": "assistant", "content": message["content"]})
            items.extend(converted)
            continue
        role = message["role"]
        if role == "tool":
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": message.get("tool_call_id") or message.get("name", ""),
                    "output": message["content"],
                }
            )
            continue
        if role == "assistant" and message.get("tool_calls"):
            calls = stored_tool_calls(message["tool_calls"], budget)
            if message.get("content"):
                items.append({"role": "assistant", "content": message["content"]})
            items.extend(
                {
                    "type": "function_call",
                    "call_id": call.get("id") or call["name"],
                    "name": call["name"],
                    "arguments": json.dumps(call.get("arguments", {})),
                }
                for call in calls
            )
            continue
        items.append({"role": role, "content": message["content"]})
    return items
