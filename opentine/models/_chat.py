"""Provider-neutral OpenAI Chat Completions wire adapter."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._chat_billing import chat_meter
from opentine.models._chat_request import build_messages, build_tools
from opentine.models._client import closing_client
from opentine.models._provider_meta import model_name, validated_rates
from opentine.models._stream_content import chat_content
from opentine.models._streaming import ChatStreamState, chat_chunk_usage
from opentine.models._terminal import chat_terminal
from opentine.models._usage import value


class ChatCompletions:
    """Chat Completions transport with provider-scoped catalog billing."""

    _stream_usage_providers = {"openai", "openai-compatible", "qwen", "xai"}

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
        include_usage: bool | None = None,
    ):
        self._model = model
        self._provider = provider
        self._api_key = api_key
        self._base_url = base_url
        self._omit_temperature = omit_temperature
        legacy = None
        if input_cost_per_mtok is not None or output_cost_per_mtok is not None:
            legacy = {}
            if input_cost_per_mtok is not None:
                legacy["input"] = input_cost_per_mtok
            if output_cost_per_mtok is not None:
                legacy["output"] = output_cost_per_mtok
                legacy["reasoning"] = output_cost_per_mtok
        self._rate_override = validated_rates(
            provider, model, rates if rates is not None else legacy
        )
        self._catalog = catalog
        self._service_tier = service_tier
        self._unmetered = unmetered
        self._include_usage = include_usage

    @property
    def name(self) -> str:
        return self._model

    @property
    def supports_tools(self) -> bool:
        return True

    @property
    def supports_thinking(self) -> bool:
        name = self._model.lower()
        return any(
            item in name
            for item in (
                "reason",
                "thinking",
                "gpt-5",
                "grok-4",
                "kimi-k3",
                "kimi-k2",
                "deepseek-v4",
                "glm-5",
                "qwen3",
                "mistral",
                "ministral",
            )
        )

    def _get_client(self):
        try:
            import openai
        except ImportError:
            raise ImportError("pip install opentine[compat]") from None
        return openai.AsyncOpenAI(
            api_key=self._client_api_key(),
            base_url=self._base_url,
            max_retries=0,
        )

    def _client_api_key(self) -> str:
        return self._api_key

    _build_tools = staticmethod(build_tools)
    _build_messages = staticmethod(build_messages)

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

    def _meter(
        self,
        raw_usage: Any,
        service_tier: str | None = None,
        reported_model: str | None = None,
    ) -> dict[str, Any]:
        return chat_meter(
            self._provider,
            self._model,
            raw_usage,
            self._catalog,
            self._rate_override,
            service_tier or self._service_tier,
            self._unmetered,
            reported_model,
        )

    def _billing_tier(self, messages: list[dict[str, Any]], reported: str | None) -> str | None:
        del messages
        return reported or self._service_tier

    async def _complete(
        self,
        client: Any,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        kwargs = self._kwargs(messages, tools, system, temperature)
        response = await client.chat.completions.create(**kwargs)
        choices = value(response, "choices", []) or []
        choice = choices[0] if choices else None
        result = chat_content(value(choice, "message"))
        chat_terminal(result, value(choice, "finish_reason") if choice else "empty_choices")
        tier = self._billing_tier(kwargs["messages"], value(response, "service_tier"))
        reported_model = value(response, "model")
        result.update(self._meter(value(response, "usage"), tier, reported_model))
        if normalized_model := model_name(reported_model):
            result["model"] = normalized_model
        return result

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        async with closing_client(self._get_client()) as client:
            return await self._complete(client, messages, tools, system, temperature)

    async def _stream(
        self,
        client: Any,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        kwargs = self._kwargs(messages, tools, system, temperature)
        kwargs["stream"] = True
        if self._include_usage or (
            self._include_usage is None and self._provider in self._stream_usage_providers
        ):
            kwargs["stream_options"] = {"include_usage": True}
        stream = await client.chat.completions.create(**kwargs)
        state = ChatStreamState()
        final_usage = None
        final_tier = self._service_tier
        final_model = None
        final_reason = None
        saw_choice = False
        async for chunk in stream:
            choices = value(chunk, "choices", []) or []
            if choices:
                saw_choice = True
                final_reason = value(choices[0], "finish_reason") or final_reason
                for event in state.add(value(choices[0], "delta")):
                    yield event
            raw_usage = chat_chunk_usage(chunk, choices)
            reported_model = value(chunk, "model")
            if reported_model is not None:
                final_model = reported_model
            if raw_usage:
                final_usage = raw_usage
                final_tier = self._billing_tier(kwargs["messages"], value(chunk, "service_tier"))
                yield {
                    "type": "usage",
                    **self._meter(raw_usage, final_tier, final_model),
                }
        if final_usage is None:
            yield {"type": "usage", **self._meter(None, final_tier, final_model)}
        response = state.result()
        terminal_reason = final_reason if saw_choice else "empty_choices"
        if saw_choice and not terminal_reason:
            terminal_reason = "stream_ended_without_terminal_reason"
        chat_terminal(response, terminal_reason)
        if normalized_model := model_name(final_model):
            response["model"] = normalized_model
        if (
            response["tool_calls"]
            or response.get("refusal")
            or response.get("reasoning_content")
            or response.get("content_blocks")
        ):
            response.update(self._meter(final_usage, final_tier, final_model))
            yield {"type": "response", **response}

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        async with closing_client(self._get_client()) as client:
            async for event in self._stream(client, messages, tools, system, temperature):
                yield event
