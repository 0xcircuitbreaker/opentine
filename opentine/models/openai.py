"""Native OpenAI adapter using Responses, with a legacy chat fallback."""

from __future__ import annotations

import os
import re
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit

from opentine.billing import PricingCatalog
from opentine.models._chat import ChatCompletions
from opentine.models._client import closing_client
from opentine.models._responses import ResponsesTransport, omits_temperature
from opentine.models._sdk_headers import openai_first_party, openai_headers

#: OpenAI's data-residency hosts: still OpenAI's Responses API and bill (1.1x
#: for newer models via the card's ``regional`` modifier), not a compatible server.
_REGIONAL = re.compile(r"(?:us|eu|au|ca|jp|in|sg|kr|gb|ae)\.api\.openai\.com")


def regional_host(base_url: str | None) -> bool:
    host = (urlsplit(base_url).hostname or "") if base_url else ""
    return bool(_REGIONAL.fullmatch(host.lower()))


class OpenAI(ChatCompletions):
    """OpenAI models use Responses; custom base URLs use Chat Completions."""

    def __init__(
        self,
        model: str = "gpt-6.1-sol",
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
        responses: bool | None = None,
    ):
        resolved_base = base_url or os.environ.get("OPENAI_BASE_URL")
        regional = regional_host(resolved_base)
        compatible = bool(resolved_base) and not regional
        resolved_provider = (
            provider if provider is not None else ("openai-compatible" if compatible else "openai")
        )
        resolved_key = (
            api_key
            if api_key is not None
            else os.environ.get("OPENAI_COMPAT_API_KEY" if compatible else "OPENAI_API_KEY", "")
        )
        super().__init__(
            model,
            provider=resolved_provider,
            api_key=resolved_key,
            base_url=resolved_base,
            omit_temperature=omit_temperature
            or omits_temperature(model, native=resolved_provider == "openai" and not compatible),
            input_cost_per_mtok=input_cost_per_mtok,
            output_cost_per_mtok=output_cost_per_mtok,
            rates=rates,
            catalog=catalog,
            service_tier=service_tier,
            unmetered=unmetered,
        )
        # The SDK's own env headers go only to OpenAI or the env-configured gateway.
        self._env_headers = base_url is None or openai_first_party(base_url)
        # ``responses=True`` targets a compatible server's /v1/responses (vLLM,
        # LM Studio, Ollama…), recorded under its own provider.
        native = resolved_provider == "openai" and not compatible
        self._native_responses = native if responses is None else responses
        self._responses = ResponsesTransport(
            model=model,
            catalog=catalog,
            rate_override=self._rate_override,
            service_tier=service_tier,
            unmetered=unmetered,
            provider=resolved_provider,
            regional=regional,
        )

    def _billing_tier(self, messages: list[dict[str, Any]], reported: str | None) -> str | None:
        # Chat Completions on a data-residency host carries the same uplift.
        return self._responses.regional_tier(super()._billing_tier(messages, reported), None)

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
            # OPENAI_CUSTOM_HEADERS / OPENAI_ORG_ID belong to OpenAI's own API (or
            # the operator's OPENAI_BASE_URL), never to an explicit compatible host.
            default_headers=openai_headers(
                openai.Omit(), self._base_url, keep_env=self._env_headers
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
