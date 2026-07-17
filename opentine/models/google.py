"""Google Gemini adapter with normalized usage and effective-dated billing."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._client import closing_client
from opentine.models._continuation import google_sdk_parts
from opentine.models._google_billing import google_header_tier, google_meter, google_service_tier
from opentine.models._google_stream import GoogleStreamState
from opentine.models._provider_meta import model_name, validated_rates
from opentine.models._stream_content import google_content
from opentine.models._stream_limits import SizeBudget
from opentine.models._terminal import reject_refused_tool_calls
from opentine.models._tool_args import stored_tool_calls
from opentine.models._usage import value


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
        if service_tier not in (None, "standard", "flex", "priority"):
            raise ValueError("Google service_tier must be standard, flex, or priority")
        self._model = model
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY", "")
        self._rate_override = validated_rates("google", model, rates)
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
        argument_budget = SizeBudget()
        for message in messages:
            role = message["role"]
            if role == "tool":
                contents.append(
                    types.Content(
                        role="user",
                        parts=[
                            types.Part(
                                function_response=types.FunctionResponse(
                                    id=message.get("tool_call_id"),
                                    name=message.get("name", ""),
                                    response={"result": message["content"]},
                                )
                            )
                        ],
                    )
                )
                continue
            if role == "assistant" and message.get("google_content"):
                contents.append(
                    types.Content(
                        role="model",
                        parts=google_sdk_parts(types, message["google_content"]),
                    )
                )
                continue
            if role == "assistant" and message.get("tool_calls"):
                calls = stored_tool_calls(message["tool_calls"], argument_budget)
                parts: list[Any] = []
                if message.get("content"):
                    parts.append(types.Part.from_text(text=message["content"]))
                parts.extend(
                    types.Part(
                        function_call=types.FunctionCall(
                            id=call.get("id"),
                            name=call["name"],
                            args=call.get("arguments", {}),
                        )
                    )
                    for call in calls
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
        config_options: dict[str, Any] = {"temperature": temperature}
        if self._service_tier:
            config_options["service_tier"] = self._service_tier
        config = types.GenerateContentConfig(**config_options)
        if system:
            config.system_instruction = system
        converted_tools = self._build_tools(tools)
        if converted_tools:
            config.tools = converted_tools
        return contents, config

    def _meter(
        self,
        raw_usage: Any,
        reported_model: str | None = None,
        response_tier: str | None = None,
    ) -> dict[str, Any]:
        return google_meter(
            self._model,
            raw_usage,
            self._catalog,
            self._rate_override,
            google_service_tier(raw_usage, self._service_tier, response_tier),
            reported_model,
        )

    def _result(self, response: Any) -> dict[str, Any]:
        result = google_content(response)
        candidates = value(response, "candidates", []) or []
        if not candidates and not result.get("refusal"):
            result["refusal"] = "provider returned no candidates"
            result["warnings"].append(result["refusal"])
        elif candidates and not value(candidates[0], "finish_reason") and not result.get("refusal"):
            result["refusal"] = "incomplete response: missing finish reason"
            result["warnings"].append(result["refusal"])
        reported_model = value(response, "model_version") or value(response, "modelVersion")
        result.update(
            self._meter(
                value(response, "usage_metadata"),
                reported_model,
                google_header_tier(response),
            )
        )
        if normalized_model := model_name(reported_model):
            result["model"] = normalized_model
        reject_refused_tool_calls(result)
        return result

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        contents, config = self._request(messages, tools, system, temperature)
        async with closing_client(self._get_client()) as client:
            response = await client.aio.models.generate_content(
                model=self._model, contents=contents, config=config
            )
            return self._result(response)

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]:
        contents, config = self._request(messages, tools, system, temperature)
        async with closing_client(self._get_client()) as client:
            stream = await client.aio.models.generate_content_stream(
                model=self._model, contents=contents, config=config
            )
            state = GoogleStreamState()
            async for chunk in stream:
                for event in state.add(chunk):
                    yield event
            for event in state.finish(self._meter):
                yield event
