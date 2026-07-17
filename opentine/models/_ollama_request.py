"""Bounded Ollama request conversion."""

from __future__ import annotations

from typing import Any

from opentine.models._streaming import SizeBudget
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


def build_messages(messages: list[dict[str, Any]], system: str | None) -> list[dict[str, Any]]:
    converted = [{"role": "system", "content": system}] if system else []
    call_budget = SizeBudget()
    for message in messages:
        if message["role"] == "assistant" and message.get("tool_calls"):
            calls = stored_tool_calls(message["tool_calls"], call_budget)
            converted.append(
                {
                    "role": "assistant",
                    "content": message.get("content", ""),
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": call["name"],
                                "arguments": call["arguments"],
                            },
                        }
                        for call in calls
                    ],
                }
            )
        elif message["role"] == "tool":
            converted.append(
                {
                    "role": "tool",
                    "content": message["content"],
                    "tool_name": message.get("tool_name")
                    or message.get("name")
                    or message.get("tool_call_id", ""),
                }
            )
        else:
            converted.append({"role": message["role"], "content": message["content"]})
    return converted
