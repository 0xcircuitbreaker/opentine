"""Native OpenAI Responses API conversion and parsing."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from typing import Any

from opentine.billing import PricingCatalog
from opentine.models._usage import metered_response, openai_usage, value


def _plain(item: Any) -> dict[str, Any]:
    if isinstance(item, Mapping):
        return dict(item)
    dump = getattr(item, "model_dump", None)
    if callable(dump):
        return dump(exclude_none=True)
    return {
        name: raw
        for name, raw in vars(item).items()
        if not name.startswith("_") and raw is not None
    }


def response_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    if not tools:
        return None
    return [
        {
            "type": "function",
            "name": tool["name"],
            "description": tool["description"],
            "parameters": tool["input_schema"],
            "strict": bool(tool.get("strict", False)),
        }
        for tool in tools
    ]


def response_input(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for message in messages:
        preserved = message.get("response_items")
        if preserved:
            items.extend(_plain(item) for item in preserved)
            continue
        role = message["role"]
        if role == "tool":
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": message.get("tool_call_id", message.get("name", "")),
                    "output": message["content"],
                }
            )
            continue
        if role == "assistant" and message.get("tool_calls"):
            if message.get("content"):
                items.append({"role": "assistant", "content": message["content"]})
            for call in message["tool_calls"]:
                items.append(
                    {
                        "type": "function_call",
                        "call_id": call.get("id", call["name"]),
                        "name": call["name"],
                        "arguments": json.dumps(call.get("arguments", {})),
                    }
                )
            continue
        items.append({"role": role, "content": message["content"]})
    return items


def parse_response(response: Any) -> dict[str, Any]:
    text_parts: list[str] = []
    refusals: list[str] = []
    calls: list[dict[str, Any]] = []
    continuation: list[dict[str, Any]] = []
    warnings: list[str] = []
    for raw_item in value(response, "output", []) or []:
        item = _plain(raw_item)
        item_type = item.get("type")
        if item_type in {"reasoning", "function_call"}:
            continuation.append(item)
        if item_type == "function_call":
            arguments = item.get("arguments") or "{}"
            try:
                parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
            except json.JSONDecodeError:
                parsed = {"_raw": arguments}
                warnings.append(f"invalid JSON arguments for {item.get('name', '')}")
            calls.append(
                {
                    "name": item.get("name", ""),
                    "arguments": parsed,
                    "id": item.get("call_id") or item.get("id"),
                }
            )
        if item_type == "message":
            for content in item.get("content") or []:
                part = _plain(content)
                if part.get("type") == "output_text" and part.get("text"):
                    text_parts.append(part["text"])
                elif part.get("type") == "refusal" and part.get("refusal"):
                    refusals.append(part["refusal"])
    output_text = value(response, "output_text", "") or ""
    result: dict[str, Any] = {
        "text": "".join(text_parts) or output_text,
        "tool_calls": calls,
        "response_items": continuation,
        "warnings": warnings,
    }
    if refusals:
        result["refusal"] = "\n".join(refusals)
    return result


class ResponsesTransport:
    def __init__(
        self,
        *,
        model: str,
        catalog: PricingCatalog | None = None,
        rate_override: dict[str, Any] | None = None,
        service_tier: str | None = None,
    ):
        self.model = model
        self.catalog = catalog
        self.rate_override = rate_override
        self.service_tier = service_tier

    def kwargs(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str | None,
        temperature: float,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"model": self.model, "input": response_input(messages)}
        if system:
            kwargs["instructions"] = system
        converted_tools = response_tools(tools)
        if converted_tools:
            kwargs["tools"] = converted_tools
        lowered = self.model.lower()
        if not lowered.startswith(("gpt-5", "o1", "o3", "o4")):
            kwargs["temperature"] = temperature
        if self.service_tier:
            kwargs["service_tier"] = self.service_tier
        return kwargs

    def meter(self, response: Any) -> dict[str, Any]:
        return metered_response(
            "openai",
            self.model,
            openai_usage(value(response, "usage")),
            catalog=self.catalog,
            rate_override=self.rate_override,
            service_tier=value(response, "service_tier", self.service_tier),
        )

    async def complete(
        self,
        client: Any,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str | None,
        temperature: float,
    ) -> dict[str, Any]:
        response = await client.responses.create(
            **self.kwargs(messages, tools, system, temperature)
        )
        result = parse_response(response)
        result.update(self.meter(response))
        result["response_id"] = value(response, "id")
        return result

    async def stream(
        self,
        client: Any,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str | None,
        temperature: float,
    ) -> AsyncIterator[dict[str, Any]]:
        kwargs = self.kwargs(messages, tools, system, temperature)
        kwargs["stream"] = True
        events = await client.responses.create(**kwargs)
        async for event in events:
            event_type = value(event, "type", "")
            if event_type == "response.output_text.delta":
                yield {"type": "text_delta", "text": value(event, "delta", "")}
            elif event_type == "response.refusal.delta":
                yield {"type": "refusal_delta", "text": value(event, "delta", "")}
            elif event_type == "response.completed":
                response = value(event, "response")
                parsed = parse_response(response)
                parsed.update(self.meter(response))
                yield {"type": "response", **parsed}
