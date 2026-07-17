"""Request conversion for Anthropic Messages."""

from __future__ import annotations

from typing import Any

from opentine.models._continuation import anthropic_sdk_blocks
from opentine.models._stream_limits import SizeBudget
from opentine.models._tool_args import stored_tool_calls


def build_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    if not tools:
        return None
    return [
        {
            "name": tool["name"],
            "description": tool["description"],
            "input_schema": tool["input_schema"],
        }
        for tool in tools
    ]


def convert_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    converted: list[dict[str, Any]] = []
    argument_budget = SizeBudget()
    for message in messages:
        role = message["role"]
        if role == "tool":
            converted.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": message.get("tool_call_id") or message.get("name", ""),
                            "content": message["content"],
                        }
                    ],
                }
            )
            continue
        if role == "assistant" and message.get("anthropic_content"):
            converted.append(
                {
                    "role": "assistant",
                    "content": anthropic_sdk_blocks(message["anthropic_content"]),
                }
            )
            continue
        if role == "assistant" and message.get("tool_calls"):
            calls = stored_tool_calls(message["tool_calls"], argument_budget)
            content: list[dict[str, Any]] = []
            if message.get("content"):
                content.append({"type": "text", "text": message["content"]})
            content.extend(
                {
                    "type": "tool_use",
                    "id": call.get("id") or call["name"],
                    "name": call["name"],
                    "input": call.get("arguments", {}),
                }
                for call in calls
            )
            converted.append({"role": "assistant", "content": content})
            continue
        converted.append({"role": role, "content": message["content"]})
    return converted
