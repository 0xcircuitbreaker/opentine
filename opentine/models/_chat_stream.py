"""Streaming implementation shared by Chat Completions providers."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from opentine.models._provider_meta import model_name
from opentine.models._streaming import ChatStreamState, chat_chunk_usage
from opentine.models._terminal import chat_terminal
from opentine.models._usage import value


class ChatStreamMixin:
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
        observed_tier = None
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
            chunk_tier = value(chunk, "service_tier")
            if chunk_tier is not None:
                observed_tier = chunk_tier
            if raw_usage:
                final_usage = raw_usage
                if self._provider != "xai":
                    tier = self._billing_tier(kwargs["messages"], observed_tier)
                    yield {
                        "type": "usage",
                        **self._meter(
                            raw_usage, tier, final_model, observed_tier not in (None, "")
                        ),
                    }
        final_tier = self._billing_tier(kwargs["messages"], observed_tier)
        if final_usage is None:
            yield {
                "type": "usage",
                **self._meter(None, final_tier, final_model, observed_tier not in (None, "")),
            }
        elif self._provider == "xai":
            yield {
                "type": "usage",
                **self._meter(
                    final_usage, final_tier, final_model, observed_tier not in (None, "")
                ),
            }
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
            response.update(
                self._meter(final_usage, final_tier, final_model, observed_tier not in (None, ""))
            )
            yield {"type": "response", **response}
