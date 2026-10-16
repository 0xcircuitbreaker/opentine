"""Claude-Code-compatible dialects: Anthropic message objects in a JSON line stream.

*Claude-compatible* (``system``/``assistant``/``user``/``result`` lines carrying
Anthropic message objects) is the de-facto headless format: Qwen Code, Amp,
Cursor, Qoder, Auggie, Factory Droid and Grok Build emit it, each with its own
omissions -- Cursor reports no usage, Amp no model name, Qwen Code counts
``input_tokens`` *inclusive* of cache reads (it maps Gemini's
``promptTokenCount``). Claude Code itself keeps its dedicated parser
(``_claude_stream``): its assistant ``output_tokens`` is a placeholder.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentine.harnesses._dialect_base import (
    count,
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


def _blocks(message: Any) -> list[Mapping[str, Any]]:
    content = message.get("content") if isinstance(message, Mapping) else None
    return (
        [block for block in content if isinstance(block, Mapping)]
        if isinstance(content, list)
        else []
    )


class ClaudeCompatible(Dialect):
    """Anthropic-message stream (``system`` / ``assistant`` / ``user`` / ``result``)."""

    cli = "claude-compatible"
    input_includes_cache = False
    #: Event types that are progress noise (partial deltas, rate-limit notices).
    noise = frozenset({"stream_event", "rate_limit_event", "control_request", "control_response"})

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.tools: dict[str, tuple[str, Any]] = {}
        self.messages: set[str] = set()
        self.priced = False

    def tokens(self, raw: Any) -> dict[str, int]:
        if not isinstance(raw, Mapping):
            return {}
        creation = (
            raw.get("cache_creation") if isinstance(raw.get("cache_creation"), Mapping) else {}
        )
        write = count(raw.get("cache_creation_input_tokens"))
        write_1h = count(creation.get("ephemeral_1h_input_tokens"))
        source_input, output = count(raw.get("input_tokens")), count(raw.get("output_tokens"))
        reasoning = 0
        total = count(raw.get("total_tokens"))
        if self.input_includes_cache and total > source_input + output:
            reasoning = total - source_input - output  # Gemini-style: thoughts are outside both
        return usage(
            input=source_input,
            output=output,
            cache_read=raw.get("cache_read_input_tokens"),
            cache_write=max(write, write_1h),
            cache_write_1h=write_1h,
            reasoning=reasoning,
            input_includes_cache=self.input_includes_cache,
        )

    def provider_for(self, model: str) -> str:
        return self.provider

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        kind = data.get("type")
        if not isinstance(kind, str):
            return None  # an unhashable or odd ``type``: not one of this CLI's events
        if kind in self.noise:
            return []
        if kind == "system":
            return self._system(data)
        if kind == "assistant":
            return self._assistant(data)
        if kind == "user":
            return self._tool_results(data)
        if kind == "tool_call":
            return self._cursor_tool(data)
        if kind == "result":
            return self._result(data)
        return None

    def _system(self, data: Mapping[str, Any]) -> list[HarnessStep]:
        subtype = str(data.get("subtype") or "")
        if subtype.startswith("error"):
            return [error_step(data.get("error") or subtype, self.model)]
        if subtype not in ("init", "session_start"):
            return []
        self.set_model(data.get("model"))
        return [think_step("", self.model, event=subtype, session_id=data.get("session_id"))]

    def _assistant(self, data: Mapping[str, Any]) -> list[HarnessStep]:
        if data.get("model_call_id"):  # Cursor's duplicate pre-tool flush
            return []
        message = data.get("message") if isinstance(data.get("message"), Mapping) else {}
        self.set_model(message.get("model"))
        identifier = str(message.get("id") or "")
        repeated = bool(identifier) and identifier in self.messages
        if identifier:
            self.messages.add(identifier)
        blocks = _blocks(message)
        calls = []
        for block in blocks:
            if block.get("type") == "tool_use":
                call_id, name = str(block.get("id") or ""), str(block.get("name") or "tool")
                self.tools[call_id] = (name, block.get("input"))
                calls.append({"id": call_id, "name": name, "arguments": block.get("input")})
        text = text_of([b for b in blocks if b.get("type") == "text"])
        tokens = {} if repeated else self.tokens(message.get("usage"))
        if not tokens:  # no usage reported: a record, not a priceable model call
            return [think_step(text, self.model, tool_calls=calls or None)] if text or calls else []
        self.priced = True
        step = model_step(
            self.model,
            self.provider_for(self.model),
            tokens,
            text=text,
            calls=calls,
            message_id=identifier or None,
            parent_tool_use_id=data.get("parent_tool_use_id"),
        )
        return [step]

    def _tool_results(self, data: Mapping[str, Any]) -> list[HarnessStep]:
        steps = []
        for block in _blocks(data.get("message")):
            if block.get("type") != "tool_result":
                continue
            call_id = str(block.get("tool_use_id") or "")
            name, arguments = self.tools.pop(call_id, ("tool", None))
            steps.append(
                tool_step(
                    name,
                    arguments,
                    block.get("content"),
                    self.model,
                    error=bool(block.get("is_error")),
                    tool_use_id=call_id,
                )
            )
        return steps

    def _cursor_tool(self, data: Mapping[str, Any]) -> list[HarnessStep]:
        if data.get("subtype") != "completed":
            return []
        call = data.get("tool_call") if isinstance(data.get("tool_call"), Mapping) else {}
        for key, body in call.items():
            if not isinstance(body, Mapping):
                continue
            if key == "function":
                return [
                    tool_step(
                        body.get("name"), body.get("arguments"), body.get("result"), self.model
                    )
                ]
            name = key[: -len("ToolCall")] if key.endswith("ToolCall") else key
            result = body.get("result") if isinstance(body.get("result"), Mapping) else {}
            outcome = result.get("success", result.get("error"))
            error = "error" in result and "success" not in result
            return [
                tool_step(
                    name,
                    body.get("args"),
                    outcome if isinstance(outcome, str) else text_of(outcome) or str(outcome or ""),
                    self.model,
                    error=error,
                    tool_use_id=data.get("call_id"),
                )
            ]
        return []

    def _result(self, data: Mapping[str, Any]) -> list[HarnessStep]:
        steps: list[HarnessStep] = []
        if not self.priced:
            per_model = data.get("modelUsage")
            if isinstance(per_model, Mapping) and per_model:
                for model, totals in per_model.items():
                    if isinstance(totals, Mapping):
                        tokens = usage(
                            input=totals.get("inputTokens"),
                            output=totals.get("outputTokens"),
                            cache_read=totals.get("cacheReadInputTokens"),
                            cache_write=totals.get("cacheCreationInputTokens"),
                            input_includes_cache=self.input_includes_cache,
                        )
                        steps.append(
                            model_step(
                                str(model),
                                self.provider_for(str(model)),
                                tokens,
                                event="result-usage",
                            )
                        )
            elif self.tokens(data.get("usage")):
                tokens = self.tokens(data.get("usage"))
                steps.append(
                    model_step(
                        self.model, self.provider_for(self.model), tokens, event="result-usage"
                    )
                )
        failed = bool(data.get("is_error")) or str(data.get("subtype", "")).startswith("error")
        error = data.get("error")
        steps.append(
            done_step(
                data.get("result") if not failed else (text_of(error) or str(error or "")),
                self.cli,
                self.model,
                cost=money(data.get("total_cost_usd")),
                failed=failed,
                subtype=data.get("subtype"),
                num_turns=data.get("num_turns"),
                session_id=data.get("session_id"),
            )
        )
        return steps


__all__ = ["ClaudeCompatible"]
