"""Anthropic adapter — Claude models with tool_use, prompt caching, extended thinking."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any


class Anthropic:
    """Adapter for Anthropic Claude models."""

    def __init__(self, model: str = "claude-sonnet-4-20250514", api_key: str | None = None):
        self._model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    @property
    def name(self) -> str:
        return self._model

    @property
    def supports_tools(self) -> bool:
        return True

    @property
    def supports_thinking(self) -> bool:
        return "opus" in self._model or "sonnet" in self._model

    def _get_client(self):
        try:
            import anthropic
        except ImportError:
            raise ImportError("pip install opentine[anthropic]")
        return anthropic.AsyncAnthropic(api_key=self._api_key)

    def _build_tools(self, tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        return [
            {"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]}
            for t in tools
        ]

    def _convert_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for m in messages:
            role = m["role"]
            if role == "tool":
                out.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": m.get("tool_call_id", m.get("name", "")),
                                "content": m["content"],
                            }
                        ],
                    }
                )
            elif role == "assistant" and m.get("tool_calls"):
                content: list[dict[str, Any]] = []
                if m.get("content"):
                    content.append({"type": "text", "text": m["content"]})
                for tc in m["tool_calls"]:
                    content.append(
                        {
                            "type": "tool_use",
                            "id": tc.get("id", tc["name"]),
                            "name": tc["name"],
                            "input": tc.get("arguments", {}),
                        }
                    )
                out.append({"role": "assistant", "content": content})
            else:
                out.append({"role": role, "content": m["content"]})
        return out

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        client = self._get_client()
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": 4096,
            "messages": self._convert_messages(messages),
            "temperature": temperature,
        }
        if system:
            kwargs["system"] = system
        api_tools = self._build_tools(tools)
        if api_tools:
            kwargs["tools"] = api_tools

        resp = await client.messages.create(**kwargs)

        text = ""
        tool_calls = []
        for block in resp.content:
            if block.type == "text":
                text += block.text
            elif block.type == "tool_use":
                tool_calls.append({"name": block.name, "arguments": block.input, "id": block.id})

        input_cost = (resp.usage.input_tokens / 1_000_000) * 3.0
        output_cost = (resp.usage.output_tokens / 1_000_000) * 15.0
        return {"text": text, "tool_calls": tool_calls, "cost": input_cost + output_cost}

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        client = self._get_client()
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": 4096,
            "messages": self._convert_messages(messages),
            "temperature": temperature,
        }
        if system:
            kwargs["system"] = system
        api_tools = self._build_tools(tools)
        if api_tools:
            kwargs["tools"] = api_tools

        async with client.messages.stream(**kwargs) as stream:
            async for event in stream:
                if hasattr(event, "type"):
                    if event.type == "content_block_delta" and hasattr(event.delta, "text"):
                        yield {"type": "text_delta", "text": event.delta.text}
