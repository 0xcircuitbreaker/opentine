"""Native OpenAI adapter using Responses, with a legacy chat fallback."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._chat import ChatCompletions
from opentine.models._client import closing_client
from opentine.models._responses import ResponsesTransport


class OpenAI(ChatCompletions):
    """OpenAI models use Responses; custom base URLs use Chat Completions."""

    def __init__(
        self,
        model: str = "gpt-5.6",
        api_key: str | None = None,
        base_url: str | None = None,
        *,
        input_cost_per_mtok: float | None = None,
        output_cost_per_mtok: float | None = None,
        rates: dict[str, Any] | None = None,
        catalog: PricingCatalog | None = None,
        service_tier: str | None = None,
        provider: str | None = None,
        omit_temperature: bool = False,
        unmetered: bool = False,
    ):
        resolved_base = base_url or os.environ.get("OPENAI_BASE_URL")
        resolved_provider = (
            provider
            if provider is not None
            else ("openai-compatible" if resolved_base else "openai")
        )
        resolved_key = (
            api_key
            if api_key is not None
            else os.environ.get(
                "OPENAI_COMPAT_API_KEY" if resolved_base else "OPENAI_API_KEY",
                "",
            )
        )
        super().__init__(
            model,
            provider=resolved_provider,
            api_key=resolved_key,
            base_url=resolved_base,
            omit_temperature=omit_temperature,
            input_cost_per_mtok=input_cost_per_mtok,
            output_cost_per_mtok=output_cost_per_mtok,
            rates=rates,
            catalog=catalog,
            service_tier=service_tier,
            unmetered=unmetered,
        )
        self._native_responses = resolved_provider == "openai" and resolved_base is None
        self._responses = ResponsesTransport(
            model=model,
            catalog=catalog,
            rate_override=self._rate_override,
            service_tier=service_tier,
            unmetered=unmetered,
        )

    def _get_client(self):
        try:
            import openai
        except ImportError:
            raise ImportError("pip install opentine[openai]") from None
        return openai.AsyncOpenAI(
            api_key=self._api_key or "local",
            base_url=self._base_url,
            max_retries=0,
            http_client=(
                openai.DefaultAsyncHttpxClient(trust_env=False, follow_redirects=False)
                if self._base_url is not None
                else None
            ),
        )

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        async with closing_client(self._get_client()) as client:
            if self._native_responses and hasattr(client, "responses"):
                return await self._responses.complete(client, messages, tools, system, temperature)
            return await self._complete(client, messages, tools, system, temperature)

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        async with closing_client(self._get_client()) as client:
            if self._native_responses and hasattr(client, "responses"):
                async for event in self._responses.stream(
                    client, messages, tools, system, temperature
                ):
                    yield event
                return
            async for event in self._stream(client, messages, tools, system, temperature):
                yield event
