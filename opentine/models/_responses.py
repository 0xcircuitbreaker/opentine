"""Native OpenAI Responses API conversion and parsing."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from opentine.billing import PricingCatalog
from opentine.kernel import KernelError, canonical_json
from opentine.models._metered import metered_response
from opentine.models._provider_meta import model_name, validated_rates
from opentine.models._responses_request import plain as _plain
from opentine.models._responses_request import response_input, response_tools
from opentine.models._stream_content import MAX_STREAM_BLOCKS
from opentine.models._streaming import MAX_STREAM_CALLS, SizeBudget, TextBuffer, WarningList
from opentine.models._terminal import reject_unsafe_tool_calls, response_terminal
from opentine.models._tool_args import bounded_tool_arguments
from opentine.models._usage import openai_missing_usage, openai_usage, value


def parse_response(response: Any, forced_status: str | None = None) -> dict[str, Any]:
    text = TextBuffer("Responses text")
    refusal = TextBuffer("Responses refusal")
    calls: list[dict[str, Any]] = []
    continuation: list[dict[str, Any]] = []
    warnings: list[str] = WarningList()
    structured = SizeBudget()
    output = value(response, "output", []) or []
    for raw_item in output[:MAX_STREAM_BLOCKS]:
        item = _plain(raw_item)
        item_type = item.get("type")
        if item_type in {"message", "reasoning", "function_call"}:
            kept = structured.keep(item, warnings, "Responses continuation")
            if isinstance(kept, dict) and not kept.get("_truncated"):
                try:
                    canonical_json(kept)
                except (KernelError, RecursionError):
                    warnings.append(
                        "Responses continuation contained non-canonical data and was discarded"
                    )
                else:
                    continuation.append(kept)
        if item_type == "function_call":
            if len(calls) >= MAX_STREAM_CALLS:
                warnings.append(f"streamed tool calls truncated at {MAX_STREAM_CALLS} entries")
                continue
            arguments = item.get("arguments") or "{}"
            parsed = bounded_tool_arguments(
                arguments, structured, warnings, "Responses", item.get("name", "")
            )
            calls.append(
                {
                    "name": str(item.get("name", ""))[:4096],
                    "arguments": parsed,
                    "id": str(item.get("call_id") or item.get("id") or "")[:4096] or None,
                }
            )
        if item_type == "message":
            for content in (item.get("content") or [])[:MAX_STREAM_BLOCKS]:
                part = _plain(content)
                if part.get("type") == "output_text" and part.get("text"):
                    text.add(part["text"])
                elif part.get("type") == "refusal" and part.get("refusal"):
                    refusal.add(part["refusal"])
            if len(item.get("content") or []) > MAX_STREAM_BLOCKS:
                warnings.append(f"streamed content truncated at {MAX_STREAM_BLOCKS} blocks")
    if len(output) > MAX_STREAM_BLOCKS:
        warnings.append(f"streamed output truncated at {MAX_STREAM_BLOCKS} blocks")
    if not text.text:
        text.add(value(response, "output_text", "") or "")
    text.warn(warnings)
    refusal.warn(warnings)
    result: dict[str, Any] = {
        "text": text.text,
        "tool_calls": calls,
        "response_items": continuation,
        "warnings": warnings,
    }
    if refusal.text:
        result["refusal"] = refusal.text
    reject_unsafe_tool_calls(result)
    response_terminal(result, response, forced_status)
    return result


class ResponsesTransport:
    def __init__(
        self,
        *,
        model: str,
        catalog: PricingCatalog | None = None,
        rate_override: dict[str, Any] | None = None,
        service_tier: str | None = None,
        unmetered: bool = False,
    ):
        self.model = model
        self.catalog = catalog
        self.rate_override = validated_rates("openai", model, rate_override)
        self.service_tier = service_tier
        self.unmetered = unmetered

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
        raw_usage = value(response, "usage")
        reported_model = value(response, "model")
        normalized_model = model_name(reported_model)
        actual_model = normalized_model or self.model
        observed_tier = value(response, "service_tier")
        missing = openai_missing_usage(
            raw_usage,
            require_cache_write=actual_model.casefold().startswith("gpt-5.6"),
        )
        return metered_response(
            "openai",
            self.model,
            openai_usage(raw_usage),
            catalog=self.catalog,
            rate_override=self.rate_override,
            service_tier=observed_tier or self.service_tier,
            unmetered=self.unmetered,
            usage_reported=raw_usage is not None,
            missing_usage=missing,
            partitioned_usage_incomplete="cache_write_5m" in missing,
            reported_model=reported_model,
            requested_service_tier=self.service_tier,
            service_tier_observed=observed_tier not in (None, ""),
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
        if reported_model := model_name(value(response, "model")):
            result["model"] = reported_model
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
        terminal = False
        async for event in events:
            event_type = value(event, "type", "")
            if event_type == "response.output_text.delta":
                yield {"type": "text_delta", "text": value(event, "delta", "")}
            elif event_type == "response.refusal.delta":
                yield {"type": "refusal_delta", "text": value(event, "delta", "")}
            elif event_type in {"response.completed", "response.failed", "response.incomplete"}:
                terminal = True
                response = value(event, "response") or event
                parsed = parse_response(response, event_type.removeprefix("response."))
                parsed.update(self.meter(response))
                if reported_model := model_name(value(response, "model")):
                    parsed["model"] = reported_model
                yield {"type": "response", **parsed}
            elif event_type in {"error", "response.error"}:
                terminal = True
                response = {
                    "error": value(event, "error") or event,
                    "model": value(event, "model"),
                    "status": "failed",
                    "usage": value(event, "usage"),
                }
                parsed = parse_response(response)
                parsed.update(self.meter(response))
                yield {"type": "response", **parsed}
        if not terminal:
            metered = self.meter(None)
            yield {"type": "usage", **metered}
            parsed = {"text": "", "tool_calls": [], "warnings": []}
            response_terminal(
                parsed,
                {"incomplete_details": {"reason": "stream ended before terminal event"}},
                "incomplete",
            )
            parsed.update(metered)
            yield {"type": "response", **parsed}
