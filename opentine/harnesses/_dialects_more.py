"""Goose and GitHub Copilot CLI dialects.

* Goose ``run --output-format stream-json`` (``crates/goose-cli/src/session``):
  ``message`` events carry Goose messages (``toolRequest`` / ``toolResponse``
  content); ``complete`` carries session totals whose ``input_tokens`` include
  cache reads and writes (Goose sums them per provider).
* Copilot CLI ``--output-format json``: the SDK's session events
  (``github/copilot-sdk`` ``session-events.ts``). ``assistant.usage`` names the
  model per API call; its ``cost`` is a premium-request *multiplier*, not USD,
  so it is never booked.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentine.harnesses._dialect_base import (
    done_step,
    error_step,
    model_step,
    money,
    text_of,
    think_step,
    tool_step,
    usage,
)
from opentine.harnesses._dialect_harness import Dialect
from opentine.harnesses._types import HarnessStep


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


class Goose(Dialect):
    cli = "goose"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        if not self.model:
            self.set_model(self.env.get("GOOSE_MODEL"), self.env.get("GOOSE_PROVIDER"))
        elif not self.provider:
            self.set_model(self.model, self.env.get("GOOSE_PROVIDER"))
        self.tools: dict[str, tuple[str, Any]] = {}

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        kind = data.get("type")
        if kind == "message":
            return self._message(_map(data.get("message")))
        if kind == "error":
            return [error_step(data.get("error"), self.model)]
        if kind == "complete":
            tokens = usage(
                input=data.get("input_tokens"),
                output=data.get("output_tokens"),
                cache_read=data.get("cache_read_input_tokens"),
                cache_write=data.get("cache_write_input_tokens"),
                input_includes_cache=True,
            )
            steps = (
                [model_step(self.model, self.provider, tokens, event="session-totals")]
                if tokens
                else []
            )
            return [*steps, done_step("", self.cli, self.model, cost=money(data.get("cost_usd")))]
        if kind == "notification":
            return []
        return None

    def _message(self, message: Mapping[str, Any]) -> list[HarnessStep]:
        steps: list[HarnessStep] = []
        content = message.get("content") if isinstance(message.get("content"), list) else []
        for block in content:
            block = _map(block)
            kind = block.get("type")
            if kind == "toolRequest":
                call = _map(_map(block.get("toolCall")).get("value"))
                self.tools[str(block.get("id"))] = (
                    str(call.get("name") or "tool"),
                    call.get("arguments"),
                )
            elif kind == "toolResponse":
                name, arguments = self.tools.pop(str(block.get("id")), ("tool", None))
                result = _map(block.get("toolResult"))
                value = result.get("value")
                value = value.get("content") if isinstance(value, Mapping) else value
                steps.append(
                    tool_step(
                        name,
                        arguments,
                        text_of(value) or str(value or ""),
                        self.model,
                        error=result.get("status") == "error",
                        tool_use_id=block.get("id"),
                    )
                )
            elif kind in ("text", "thinking") and message.get("role") == "assistant":
                text = str(block.get("text") or block.get("thinking") or "")
                if text.strip():
                    steps.append(think_step(text, self.model, event=kind))
        return steps


class Copilot(Dialect):
    cli = "copilot"
    default_provider = "github-copilot"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.tools: dict[str, tuple[str, Any]] = {}

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        kind, body = data.get("type"), _map(data.get("data"))
        if kind == "assistant.usage":
            self.set_model(body.get("model"))
            tokens = usage(
                input=body.get("inputTokens"),
                output=body.get("outputTokens"),
                cache_read=body.get("cacheReadTokens"),
                cache_write=body.get("cacheWriteTokens"),
                reasoning=body.get("reasoningTokens"),
                input_includes_cache=True,
                output_includes_reasoning=True,
            )
            # ``cost`` is a premium-request multiplier, not dollars: kept, never booked.
            return [
                model_step(
                    self.model,
                    self.provider,
                    tokens,
                    api_call_id=body.get("apiCallId"),
                    premium_multiplier=body.get("cost"),
                    initiator=body.get("initiator"),
                )
            ]
        if kind == "tool.execution_start":
            self.tools[str(body.get("toolCallId"))] = (
                str(body.get("toolName") or "tool"),
                body.get("arguments"),
            )
            return []
        if kind == "tool.execution_complete":
            name, arguments = self.tools.pop(str(body.get("toolCallId")), ("tool", None))
            failed = body.get("success") is False
            result = (
                _map(body.get("error")).get("message")
                if failed
                else _map(body.get("result")).get("content")
            )
            return [
                tool_step(
                    name,
                    arguments,
                    result,
                    self.model,
                    error=failed,
                    tool_use_id=body.get("toolCallId"),
                )
            ]
        if kind == "assistant.message":
            text = str(body.get("content") or "")
            return [think_step(text, self.model)] if text.strip() else []
        if kind == "session.error":
            return [error_step(body.get("message") or body, self.model)]
        return [] if isinstance(kind, str) and "." in kind else None


__all__ = ["Copilot", "Goose"]
