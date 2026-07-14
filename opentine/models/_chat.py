"""Provider-neutral OpenAI Chat Completions wire adapter."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._usage import metered_response, openai_usage, value


class ChatCompletions:
    """Chat Completions transport with provider-scoped catalog billing."""

    def __init__(
        self,
        model: str,
        *,
        provider: str,
        api_key: str = "",
        base_url: str | None = None,
        omit_temperature: bool = False,
        input_cost_per_mtok: float | None = None,
        output_cost_per_mtok: float | None = None,
        rates: dict[str, Any] | None = None,
        catalog: PricingCatalog | None = None,
        service_tier: str | None = None,
        unmetered: bool = False,
    ):
        self._model = model
        self._provider = provider
        self._api_key = api_key
        self._base_url = base_url
        self._omit_temperature = omit_temperature
        legacy = None
        if input_cost_per_mtok is not None or output_cost_per_mtok is not None:
            legacy = {
                "input": input_cost_per_mtok or 0,
                "output": output_cost_per_mtok or 0,
                "reasoning": output_cost_per_mtok or 0,
            }
        self._rate_override = rates if rates is not None else legacy
        self._catalog = catalog
        self._service_tier = service_tier
        self._unmetered = unmetered

    @property
    def name(self) -> str:
        return self._model

    @property
    def supports_tools(self) -> bool:
        return True

    @property
    def supports_thinking(self) -> bool:
        name = self._model.lower()
        return any(item in name for item in ("reason", "thinking", "gpt-5", "grok-4", "kimi-k2"))

    def _get_client(self):
        try:
            import openai
        except ImportError:
            raise ImportError("pip install opentine[compat]") from None
        return openai.AsyncOpenAI(api_key=self._api_key, base_url=self._base_url)

    @staticmethod
    def _build_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
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

    @staticmethod
    def _build_messages(messages: list[dict[str, Any]], system: str | None) -> list[dict[str, Any]]:
        converted: list[dict[str, Any]] = []
        if system:
            converted.append({"role": "system", "content": system})
        for message in messages:
            role = message["role"]
            if role == "tool":
                converted.append(
                    {
                        "role": "tool",
                        "content": message["content"],
                        "tool_call_id": message.get("tool_call_id", message.get("name", "")),
                    }
                )
                continue
            if role == "assistant" and message.get("tool_calls"):
                item: dict[str, Any] = {
                    "role": "assistant",
                    "content": message.get("content") or "",
                    "tool_calls": [
                        {
                            "id": call.get("id", call["name"]),
                            "type": "function",
                            "function": {
                                "name": call["name"],
                                "arguments": json.dumps(call.get("arguments", {})),
                            },
                        }
                        for call in message["tool_calls"]
                    ],
                }
                if message.get("reasoning_content"):
                    item["reasoning_content"] = message["reasoning_content"]
                converted.append(item)
                continue
            converted.append({"role": role, "content": message["content"]})
        return converted

    def _kwargs(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str | None,
        temperature: float,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": self._build_messages(messages, system),
        }
        if not self._omit_temperature:
            kwargs["temperature"] = temperature
        api_tools = self._build_tools(tools)
        if api_tools:
            kwargs["tools"] = api_tools
        if self._service_tier:
            kwargs["service_tier"] = self._service_tier
        return kwargs

    def _meter(self, raw_usage: Any, service_tier: str | None = None) -> dict[str, Any]:
        return metered_response(
            self._provider,
            self._model,
            openai_usage(raw_usage),
            catalog=self._catalog,
            rate_override=self._rate_override,
            service_tier=service_tier or self._service_tier,
            unmetered=self._unmetered,
        )

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        response = await self._get_client().chat.completions.create(
            **self._kwargs(messages, tools, system, temperature)
        )
        choice = response.choices[0]
        message = choice.message
        calls: list[dict[str, Any]] = []
        warnings: list[str] = []
        for call in value(message, "tool_calls", []) or []:
            function = value(call, "function")
            raw_arguments = value(function, "arguments", "{}")
            try:
                arguments = (
                    json.loads(raw_arguments) if isinstance(raw_arguments, str) else raw_arguments
                )
            except json.JSONDecodeError:
                arguments = {"_raw": raw_arguments}
                warnings.append(f"invalid JSON arguments for {value(function, 'name', '')}")
            calls.append(
                {
                    "name": value(function, "name", ""),
                    "arguments": arguments,
                    "id": value(call, "id"),
                }
            )
        result: dict[str, Any] = {
            "text": value(message, "content", "") or "",
            "tool_calls": calls,
            "warnings": warnings,
        }
        refusal = value(message, "refusal")
        if refusal:
            result["refusal"] = refusal
        reasoning = value(message, "reasoning_content")
        if reasoning:
            result["reasoning_content"] = reasoning
        result.update(self._meter(value(response, "usage"), value(response, "service_tier")))
        return result

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        kwargs = self._kwargs(messages, tools, system, temperature)
        kwargs["stream"] = True
        if self._provider in {"openai", "xai"}:
            kwargs["stream_options"] = {"include_usage": True}
        stream = await self._get_client().chat.completions.create(**kwargs)
        async for chunk in stream:
            choices = value(chunk, "choices", []) or []
            if choices:
                delta = value(choices[0], "delta")
                text = value(delta, "content")
                if text:
                    yield {"type": "text_delta", "text": text}
            raw_usage = value(chunk, "usage")
            if raw_usage:
                yield {"type": "usage", **self._meter(raw_usage, value(chunk, "service_tier"))}


def env_key(name: str) -> str:
    return os.environ.get(name, "")
