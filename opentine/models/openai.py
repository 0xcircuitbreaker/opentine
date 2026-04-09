"""OpenAI adapter — GPT, o-series, function calling."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from typing import Any


class OpenAI:
    """Adapter for OpenAI models."""

    def __init__(self, model: str = "gpt-4o", api_key: str | None = None):
        self._model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    @property
    def name(self) -> str:
        return self._model

    @property
    def supports_tools(self) -> bool:
        return True

    @property
    def supports_thinking(self) -> bool:
        return self._model.startswith("o")

    def _get_client(self):
        try:
            import openai
        except ImportError:
            raise ImportError("pip install opentine[openai]")
        return openai.AsyncOpenAI(api_key=self._api_key)

    def _build_tools(self, tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        client = self._get_client()
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        for m in messages:
            if m["role"] == "tool":
                msgs.append(
                    {
                        "role": "tool",
                        "content": m["content"],
                        "tool_call_id": m.get("tool_call_id", m.get("name", "")),
                    }
                )
            else:
                msgs.append({"role": m["role"], "content": m["content"]})

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": msgs,
            "temperature": temperature,
        }
        api_tools = self._build_tools(tools)
        if api_tools:
            kwargs["tools"] = api_tools

        resp = await client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        text = choice.message.content or ""
        tool_calls = []
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                tool_calls.append(
                    {
                        "name": tc.function.name,
                        "arguments": json.loads(tc.function.arguments),
                        "id": tc.id,
                    }
                )

        cost = 0.0
        if resp.usage:
            input_cost = (resp.usage.prompt_tokens / 1_000_000) * 2.5
            output_cost = (resp.usage.completion_tokens / 1_000_000) * 10.0
            cost = input_cost + output_cost
        return {"text": text, "tool_calls": tool_calls, "cost": cost}

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        client = self._get_client()
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        for m in messages:
            if m["role"] == "tool":
                msgs.append(
                    {
                        "role": "tool",
                        "content": m["content"],
                        "tool_call_id": m.get("tool_call_id", m.get("name", "")),
                    }
                )
            else:
                msgs.append({"role": m["role"], "content": m["content"]})

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": msgs,
            "temperature": temperature,
            "stream": True,
        }
        api_tools = self._build_tools(tools)
        if api_tools:
            kwargs["tools"] = api_tools

        stream = await client.chat.completions.create(**kwargs)
        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                yield {"type": "text_delta", "text": chunk.choices[0].delta.content}
