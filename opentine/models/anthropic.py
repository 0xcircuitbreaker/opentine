"""Anthropic Messages adapter with cache/refusal-aware billing."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._anthropic_request import build_tools, convert_messages
from opentine.models._anthropic_rules import model_rules, pricing_tier, validate_service_tier
from opentine.models._client import closing_client
from opentine.models._metered import metered_response
from opentine.models._provider_meta import model_name, validated_rates
from opentine.models._stream_content import anthropic_content
from opentine.models._terminal import reject_refused_tool_calls
from opentine.models._usage import (
    anthropic_usage,
    missing_usage_dimensions,
    value,
)


class Anthropic:
    _build_tools = staticmethod(build_tools)
    _convert_messages = staticmethod(convert_messages)

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
        validate_service_tier(service_tier)
        self._model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._rate_override = validated_rates("anthropic", model, rates)
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
        return model_rules(self._model)[0]

    @property
    def _adaptive(self) -> bool:
        return model_rules(self._model)[1]

    def _get_client(self):
        try:
            import anthropic
        except ImportError:
            raise ImportError("pip install opentine[anthropic]") from None
        return anthropic.AsyncAnthropic(api_key=self._api_key, max_retries=0)

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
            "messages": convert_messages(messages),
        }
        if not self._adaptive:
            kwargs["temperature"] = temperature
        if system:
            kwargs["system"] = system
        api_tools = build_tools(tools)
        if api_tools:
            kwargs["tools"] = api_tools
        if self._service_tier:
            kwargs["service_tier"] = self._service_tier
        if model_rules(self._model)[2]:
            kwargs["thinking"] = {"type": "adaptive"}
        if self._inference_geo:
            kwargs["inference_geo"] = self._inference_geo
        return kwargs

    def _meter(self, response: Any, *, early_refusal: bool = False) -> dict[str, Any]:
        raw_usage = value(response, "usage")
        raw_model = value(response, "model")
        reported_model = model_name(raw_model)
        payload = metered_response(
            "anthropic",
            self._model,
            anthropic_usage(raw_usage),
            catalog=self._catalog,
            rate_override=self._rate_override,
            service_tier=pricing_tier(response, self._service_tier, self._inference_geo),
            usage_reported=raw_usage is not None,
            missing_usage=missing_usage_dimensions(
                raw_usage, {"input": ("input_tokens",), "output": ("output_tokens",)}
            ),
            reported_model=raw_model,
        )
        refusal_model = self._model if raw_model is None else reported_model or ""
        billing = payload["billing"]
        if (
            early_refusal
            and refusal_model.casefold() == "claude-fable-5"
            and billing["rate_card_id"] is not None
        ):
            billing["status"] = "complete"
            billing["amount_usd"] = "0"
            billing["known_subtotal_usd"] = "0"
            billing["warnings"].append("early empty refusal is non-billable")
            billing["calculation"]["refusal_modifier"] = "0"
            payload["cost"] = 0.0
        return payload

    def _result(self, response: Any) -> dict[str, Any]:
        result = anthropic_content(response)
        stop_reason = value(response, "stop_reason")
        refused = stop_reason == "refusal" or bool(result.get("refusal"))
        successful = stop_reason in {"end_turn", "tool_use", "stop_sequence"}
        incomplete = not refused and not successful
        had_content = bool(
            result["text"]
            or result["tool_calls"]
            or result.get("reasoning_content")
            or result.get("anthropic_content")
        )
        if refused and not result.get("refusal"):
            result["refusal"] = "refused"
        if incomplete:
            reason = stop_reason or "missing stop reason"
            result["refusal"] = f"incomplete response: {reason}"
            result["warnings"].append(result["refusal"])
        if refused and had_content:
            result["text"] = ""
            result["tool_calls"] = []
            for field in ("anthropic_content", "reasoning_content"):
                result.pop(field, None)
            result["warnings"].append("discarded partial output from refused response")
        raw_usage = value(response, "usage")
        usage = anthropic_usage(raw_usage)
        result.update(
            self._meter(
                response,
                early_refusal=(
                    refused
                    and not had_content
                    and usage.output == 0
                    and usage.reasoning == 0
                    and raw_usage is not None
                ),
            )
        )
        if reported_model := model_name(value(response, "model")):
            result["model"] = reported_model
        reject_refused_tool_calls(result)
        return result

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        async with closing_client(self._get_client()) as client:
            response = await client.messages.create(
                **self._kwargs(messages, tools, system, temperature)
            )
            return self._result(response)

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        async with closing_client(self._get_client()) as client:
            manager = client.messages.stream(**self._kwargs(messages, tools, system, temperature))
            async with manager as stream:
                async for event in stream:
                    if value(event, "type") == "content_block_delta":
                        delta = value(event, "delta")
                        text = value(delta, "text")
                        if text:
                            yield {"type": "text_delta", "text": text}
                        thinking = value(delta, "thinking")
                        if thinking:
                            yield {"type": "thinking_delta", "text": thinking}
                final = getattr(stream, "get_final_message", None)
                if callable(final):
                    response = await final()
                    result = self._result(response)
                    metered = {key: result[key] for key in ("billing", "cost", "provider", "usage")}
                    yield {"type": "usage", **metered}
                    if (
                        result["tool_calls"]
                        or result.get("refusal")
                        or result.get("reasoning_content")
                        or result.get("anthropic_content")
                    ):
                        yield {"type": "response", **result}
                else:
                    metered = self._meter(None)
                    yield {"type": "usage", **metered}
                    yield {
                        "type": "response",
                        "text": "",
                        "tool_calls": [],
                        "refusal": "incomplete response: stream ended without a final message",
                        "warnings": ["Anthropic stream omitted its final message"],
                        **metered,
                    }
