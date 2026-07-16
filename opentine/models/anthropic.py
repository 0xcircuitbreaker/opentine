"""Anthropic Messages adapter with cache/refusal-aware billing."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._usage import anthropic_usage, metered_response, value


class Anthropic:
    def __init__(
        self,
        model: str = "claude-sonnet-5",
        api_key: str | None = None,
        *,
        rates: dict[str, Any] | None = None,
        catalog: PricingCatalog | None = None,
        service_tier: str | None = None,
        inference_geo: str | None = None,
    ):
        self._model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._rate_override = rates
        self._catalog = catalog
        self._service_tier = service_tier
        self._inference_geo = inference_geo

    @property
    def name(self) -> str:
        return self._model

    @property
    def supports_tools(self) -> bool:
        return True

    @property
    def supports_thinking(self) -> bool:
        lowered = self._model.lower()
        return any(name in lowered for name in ("opus", "sonnet", "fable"))

    @property
    def _adaptive(self) -> bool:
        lowered = self._model.lower()
        return (
            "fable-5" in lowered
            or "sonnet-5" in lowered
            or any(f"opus-4-{minor}" in lowered for minor in range(6, 10))
        )

    def _get_client(self):
        try:
            import anthropic
        except ImportError:
            raise ImportError("pip install opentine[anthropic]") from None
        return anthropic.AsyncAnthropic(api_key=self._api_key)

    @staticmethod
    def _build_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
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

    @staticmethod
    def _convert_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        converted: list[dict[str, Any]] = []
        for message in messages:
            role = message["role"]
            if role == "tool":
                converted.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": message.get("tool_call_id", message.get("name", "")),
                                "content": message["content"],
                            }
                        ],
                    }
                )
                continue
            if role == "assistant" and message.get("tool_calls"):
                content: list[dict[str, Any]] = []
                if message.get("content"):
                    content.append({"type": "text", "text": message["content"]})
                for call in message["tool_calls"]:
                    content.append(
                        {
                            "type": "tool_use",
                            "id": call.get("id", call["name"]),
                            "name": call["name"],
                            "input": call.get("arguments", {}),
                        }
                    )
                converted.append({"role": "assistant", "content": content})
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
            "max_tokens": 4096,
            "messages": self._convert_messages(messages),
        }
        if not self._adaptive:
            kwargs["temperature"] = temperature
        if system:
            kwargs["system"] = system
        api_tools = self._build_tools(tools)
        if api_tools:
            kwargs["tools"] = api_tools
        if self._service_tier:
            kwargs["service_tier"] = self._service_tier
        if self._inference_geo:
            kwargs["inference_geo"] = self._inference_geo
        return kwargs

    def _pricing_tier(self, response: Any) -> str | None:
        usage = value(response, "usage")
        tier = value(response, "service_tier", self._service_tier)
        geo = value(usage, "inference_geo", self._inference_geo)
        if geo != "us":
            return tier
        if tier in (None, "", "default", "standard", "standard_only"):
            return "us"
        return f"{tier}_us"

    def _meter(self, response: Any, *, early_refusal: bool = False) -> dict[str, Any]:
        payload = metered_response(
            "anthropic",
            self._model,
            anthropic_usage(value(response, "usage")),
            catalog=self._catalog,
            rate_override=self._rate_override,
            service_tier=self._pricing_tier(response),
        )
        if early_refusal:
            billing = payload["billing"]
            billing["status"] = "complete"
            billing["amount_usd"] = "0"
            billing["known_subtotal_usd"] = "0"
            billing["warnings"].append("early empty refusal is non-billable")
            billing["calculation"]["refusal_modifier"] = "0"
            payload["cost"] = 0.0
        return payload

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        response = await self._get_client().messages.create(
            **self._kwargs(messages, tools, system, temperature)
        )
        text_parts: list[str] = []
        calls: list[dict[str, Any]] = []
        refusals: list[str] = []
        for block in value(response, "content", []) or []:
            block_type = value(block, "type")
            if block_type == "text":
                text_parts.append(value(block, "text", ""))
            elif block_type == "tool_use":
                calls.append(
                    {
                        "name": value(block, "name", ""),
                        "arguments": value(block, "input", {}),
                        "id": value(block, "id"),
                    }
                )
            elif block_type == "refusal":
                refusals.append(value(block, "refusal", value(block, "text", "")))
        text = "".join(text_parts)
        refused = value(response, "stop_reason") == "refusal" or bool(refusals)
        result: dict[str, Any] = {"text": text, "tool_calls": calls}
        if refused:
            result["refusal"] = "\n".join(refusals) or "refused"
        usage = anthropic_usage(value(response, "usage"))
        early_refusal = refused and not text and not calls and usage.output == 0
        result.update(self._meter(response, early_refusal=early_refusal))
        return result

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        manager = self._get_client().messages.stream(
            **self._kwargs(messages, tools, system, temperature)
        )
        async with manager as stream:
            async for event in stream:
                if value(event, "type") == "content_block_delta":
                    delta = value(event, "delta")
                    text = value(delta, "text")
                    if text:
                        yield {"type": "text_delta", "text": text}
            final = getattr(stream, "get_final_message", None)
            if callable(final):
                response = await final()
                yield {"type": "usage", **self._meter(response)}
