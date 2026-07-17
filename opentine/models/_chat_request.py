"""Request conversion for OpenAI-compatible Chat Completions APIs."""

from __future__ import annotations

import json
from typing import Any

from opentine.models._chat_blocks import parse_chat_blocks
from opentine.models._stream_limits import MAX_STREAM_CHARS, SizeBudget
from opentine.models._tool_args import stored_tool_calls


def build_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    if not tools:
        return None
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"],
            },
        }
        for tool in tools
    ]


def _stored_content(message: dict[str, Any]) -> Any:
    if "content_blocks" not in message:
        return message.get("content", "")
    raw = message["content_blocks"]
    _, _, normalized, warnings = parse_chat_blocks(raw)
    if warnings or normalized != raw:
        raise ValueError("stored Chat content blocks are not safely normalized")
    return normalized


def build_messages(messages: list[dict[str, Any]], system: str | None) -> list[dict[str, Any]]:
    converted: list[dict[str, Any]] = []
    argument_budget = SizeBudget()
    if system:
        converted.append({"role": "system", "content": system})
    for message in messages:
        role = message["role"]
        if role == "tool":
            converted.append(
                {
                    "role": "tool",
                    "content": message["content"],
                    "tool_call_id": message.get("tool_call_id") or message.get("name", ""),
                }
            )
            continue
        content = _stored_content(message)
        reasoning = message.get("reasoning_content") if role == "assistant" else None
        if reasoning is not None and (
            not isinstance(reasoning, str) or len(reasoning) > MAX_STREAM_CHARS
        ):
            raise ValueError("stored Chat reasoning exceeds the safe size")
        if role == "assistant" and isinstance(content, str) and len(content) > MAX_STREAM_CHARS:
            raise ValueError("stored Chat content exceeds the safe size")
        if role == "assistant" and message.get("tool_calls"):
            calls = stored_tool_calls(message["tool_calls"], argument_budget)
            item: dict[str, Any] = {
                "role": "assistant",
                "content": content,
                "tool_calls": [
                    {
                        "id": call["id"],
                        "type": "function",
                        "function": {
                            "name": call["name"],
                            "arguments": json.dumps(
                                call["arguments"],
                                allow_nan=False,
                                ensure_ascii=False,
                                separators=(",", ":"),
                            ),
                        },
                    }
                    for call in calls
                ],
            }
            if reasoning and not message.get("content_blocks"):
                item["reasoning_content"] = reasoning
            converted.append(item)
            continue
        item = {"role": role, "content": content}
        if (
            role == "assistant"
            and message.get("reasoning_content")
            and not message.get("content_blocks")
        ):
            item["reasoning_content"] = message["reasoning_content"]
        converted.append(item)
    return converted
