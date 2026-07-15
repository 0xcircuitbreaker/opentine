"""Google Gemini adapter with normalized usage and effective-dated billing."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._usage import google_usage, metered_response, value


class Google:
    def __init__(
        self,
        model: str = "gemini-3.5-flash",
        api_key: str | None = None,
        *,
        rates: dict[str, Any] | None = None,
        catalog: PricingCatalog | None = None,
        service_tier: str | None = None,
    ):
        if service_tier not in (None, "standard"):
            raise ValueError(
                "Google service tiers require a provider batch, flex, or priority API; "
                "GenerateContent uses standard pricing"
            )
        self._model = model
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY", "")
        self._rate_override = rates
        self._catalog = catalog
        self._service_tier = service_tier

    @property
    def name(self) -> str:
        return self._model

    @property
    def supports_tools(self) -> bool:
        return True

    @property
    def supports_thinking(self) -> bool:
        lowered = self._model.lower()
        return "thinking" in lowered or lowered.startswith("gemini-3") or "2.5-pro" in lowered

    def _get_client(self):
        try:
            from google import genai
        except ImportError:
            raise ImportError("pip install opentine[google]") from None
        return genai.Client(api_key=self._api_key)

    @staticmethod
    def _types():
        try:
            from google.genai import types
        except ImportError:
            raise ImportError("pip install opentine[google]") from None
        return types

    def _build_tools(self, tools: list[dict[str, Any]] | None):
        if not tools:
            return None
        types = self._types()
        declarations = [
            types.FunctionDeclaration(
                name=tool["name"],
                description=tool["description"],
                parameters=tool["input_schema"],
            )
            for tool in tools
        ]
        return [types.Tool(function_declarations=declarations)]

    def _request(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str | None,
        temperature: float,
    ) -> tuple[list[Any], Any]:
        types = self._types()
        contents: list[Any] = []
        for message in messages:
            role = message["role"]
            if role == "tool":
                contents.append(
                    types.Content(
                        role="user",
                        parts=[
                            types.Part.from_function_response(
                                name=message.get("name", ""),
                                response={"result": message["content"]},
                            )
                        ],
                    )
                )
                continue
            if role == "assistant" and message.get("tool_calls"):
                parts: list[Any] = []
                if message.get("content"):
                    parts.append(types.Part.from_text(text=message["content"]))
                parts.extend(
                    types.Part.from_function_call(name=call["name"], args=call.get("arguments", {}))
                    for call in message["tool_calls"]
                )
                contents.append(types.Content(role="model", parts=parts))
                continue
            mapped_role = "model" if role == "assistant" else "user"
            contents.append(
                types.Content(
                    role=mapped_role,
                    parts=[types.Part.from_text(text=message["content"])],
                )
            )
        config = types.GenerateContentConfig(temperature=temperature)
        if system:
            config.system_instruction = system
        converted_tools = self._build_tools(tools)
        if converted_tools:
            config.tools = converted_tools
        return contents, config

    def _meter(self, raw_usage: Any) -> dict[str, Any]:
        return metered_response(
            "google",
            self._model,
            google_usage(raw_usage),
            catalog=self._catalog,
            rate_override=self._rate_override,
            service_tier=self._service_tier,
        )

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        contents, config = self._request(messages, tools, system, temperature)
        response = await self._get_client().aio.models.generate_content(
            model=self._model, contents=contents, config=config
        )
        try:
            text = response.text or ""
        except (AttributeError, ValueError):
            text = ""
        calls: list[dict[str, Any]] = []
        candidates = value(response, "candidates", []) or []
        if candidates and value(candidates[0], "content"):
            for part in value(value(candidates[0], "content"), "parts", []) or []:
                function = value(part, "function_call")
                if function:
                    calls.append(
                        {
                            "name": value(function, "name", ""),
                            "arguments": dict(value(function, "args", {}) or {}),
                            "id": value(function, "id"),
                        }
                    )
        result: dict[str, Any] = {"text": text, "tool_calls": calls}
        result.update(self._meter(value(response, "usage_metadata")))
        return result

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        contents, config = self._request(messages, tools, system, temperature)
        stream = await self._get_client().aio.models.generate_content_stream(
            model=self._model, contents=contents, config=config
        )
        final_usage = None
        async for chunk in stream:
            text = value(chunk, "text")
            if text:
                yield {"type": "text_delta", "text": text}
            if value(chunk, "usage_metadata"):
                final_usage = value(chunk, "usage_metadata")
        if final_usage:
            yield {"type": "usage", **self._meter(final_usage)}
