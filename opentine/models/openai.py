"""Native OpenAI adapter using Responses, with a legacy chat fallback."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._chat import ChatCompletions
from opentine.models._responses import ResponsesTransport


class OpenAI(ChatCompletions):
    """OpenAI models use Responses; custom base URLs use Chat Completions."""

    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: str | None = None,
        base_url: str | None = None,
        *,
        input_cost_per_mtok: float | None = None,
        output_cost_per_mtok: float | None = None,
        rates: dict[str, Any] | None = None,
        catalog: PricingCatalog | None = None,
        service_tier: str | None = None,
        provider: str = "openai",
        omit_temperature: bool = False,
        unmetered: bool = False,
    ):
        resolved_base = base_url or os.environ.get("OPENAI_BASE_URL")
        super().__init__(
            model,
            provider=provider,
            api_key=api_key or os.environ.get("OPENAI_API_KEY", ""),
            base_url=resolved_base,
            omit_temperature=omit_temperature,
            input_cost_per_mtok=input_cost_per_mtok,
            output_cost_per_mtok=output_cost_per_mtok,
            rates=rates,
            catalog=catalog,
            service_tier=service_tier,
            unmetered=unmetered,
        )
        self._native_responses = provider == "openai" and resolved_base is None
        self._responses = ResponsesTransport(
            model=model,
            catalog=catalog,
            rate_override=self._rate_override,
            service_tier=service_tier,
        )

    def _get_client(self):
        try:
            import openai
        except ImportError:
            raise ImportError("pip install opentine[openai]") from None
        return openai.AsyncOpenAI(api_key=self._api_key, base_url=self._base_url)

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        client = self._get_client()
        if self._native_responses and hasattr(client, "responses"):
            return await self._responses.complete(client, messages, tools, system, temperature)
        return await super().complete(messages, tools, system, temperature)

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        client = self._get_client()
        if self._native_responses and hasattr(client, "responses"):
            async for event in self._responses.stream(client, messages, tools, system, temperature):
                yield event
            return
        async for event in super().stream(messages, tools, system, temperature):
            yield event
