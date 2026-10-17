"""Event dialects for Pi and OpenCode.

* Pi ``--mode json`` (``packages/coding-agent/docs/json.md``): every completed
  assistant message (``message_end``) carries provider, model and usage in
  exclusive buckets, ``reasoning`` already inside ``output``, and Pi's own
  ``cost.total``.
* OpenCode ``run --format json`` (``packages/cli/src/run/noninteractive.ts``):
  ``step_finish`` carries one step's ``tokens`` (exclusive buckets; their sum is
  the total) and ``cost``; the model is the ``--model provider/model`` the run
  was started with.
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


class Pi(Dialect):
    cli = "pi"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.arguments: dict[str, Any] = {}

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        kind = data.get("type")
        if kind == "message_end":
            return self._message(_map(data.get("message")))
        if kind == "tool_execution_start":
            self.arguments[str(data.get("toolCallId"))] = data.get("args")
            return []
        if kind == "tool_execution_end":
            arguments = self.arguments.pop(str(data.get("toolCallId")), data.get("args"))
            return [
                tool_step(
                    data.get("toolName"),
                    arguments,
                    _map(data.get("result")).get("content"),
                    self.model,
                    error=bool(data.get("isError")),
                    tool_use_id=data.get("toolCallId"),
                )
            ]
        if kind == "agent_end":
            return [done_step("", self.cli, self.model, will_retry=data.get("willRetry"))]
        if kind in ("auto_retry_end",) and data.get("success") is False:
            return [error_step(data.get("finalError"), self.model)]
        return [] if isinstance(kind, str) else None

    def _message(self, message: Mapping[str, Any]) -> list[HarnessStep]:
        if message.get("role") != "assistant":
            return []
        self.set_model(
            message.get("responseModel") or message.get("model"), message.get("provider")
        )
        raw = _map(message.get("usage"))
        tokens = usage(
            input=raw.get("input"),
            output=raw.get("output"),
            cache_read=raw.get("cacheRead"),
            cache_write=raw.get("cacheWrite"),
            cache_write_1h=raw.get("cacheWrite1h"),
            reasoning=raw.get("reasoning"),
            output_includes_reasoning=True,
        )
        content = message.get("content") if isinstance(message.get("content"), list) else []
        calls = [
            {"id": b.get("id"), "name": b.get("name"), "arguments": b.get("arguments")}
            for b in content
            if isinstance(b, Mapping) and b.get("type") == "toolCall"
        ]
        steps = [
            model_step(
                self.model,
                self.provider,
                tokens,
                text=text_of(content),
                calls=calls,
                cost=money(_map(raw.get("cost")).get("total")),
                stop_reason=message.get("stopReason"),
            )
        ]
        if message.get("stopReason") == "error":
            steps.append(error_step(message.get("errorMessage"), self.model))
        return steps


class OpenCode(Dialect):
    cli = "opencode"

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        kind, part = data.get("type"), _map(data.get("part"))
        if kind in ("text", "reasoning"):
            text = str(part.get("text") or "")
            return [think_step(text, self.model, event=kind)] if text.strip() else []
        if kind == "tool_use":
            state = _map(part.get("state"))
            failed = state.get("status") == "error"
            return [
                tool_step(
                    part.get("tool"),
                    state.get("input"),
                    state.get("error") if failed else state.get("output"),
                    self.model,
                    error=failed,
                    tool_use_id=part.get("id"),
                )
            ]
        if kind == "step_finish":
            raw, cache = _map(part.get("tokens")), _map(_map(part.get("tokens")).get("cache"))
            tokens = usage(
                input=raw.get("input"),
                output=raw.get("output"),
                reasoning=raw.get("reasoning"),
                cache_read=cache.get("read"),
                cache_write=cache.get("write"),
            )
            return [
                model_step(
                    self.model,
                    self.provider,
                    tokens,
                    cost=money(part.get("cost")),
                    finish=part.get("reason"),
                )
            ]
        if kind == "error":
            error = _map(data.get("error"))
            return [error_step(error.get("message") or error, self.model)]
        if kind == "step_start":
            return []
        return None


__all__ = ["OpenCode", "Pi"]
