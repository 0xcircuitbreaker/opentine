"""Claude Code ``--output-format stream-json`` events -> priceable harness steps.

Read off a live capture (Claude Code, 2026-10), not the docs alone, because one
detail decides whether a run prices correctly: an ``assistant`` event's
``message.usage`` is the usage *at message start*. Its input side -- input, cache
reads, and cache writes split by TTL -- is exact and sums to the session total,
but its ``output_tokens`` is a placeholder (16 and 4 against a true 120 in the
capture). The final ``result`` event's ``modelUsage`` carries the true per-model
totals. So each model call becomes a step with its exact input-side usage, and
the ``result`` adds one step per model with the output (plus any input-side
remainder no message reported), making per-model totals equal Claude Code's own.
"""

from __future__ import annotations

import math
import os
from collections.abc import Callable, Mapping
from typing import Any

from opentine.core import StepKind
from opentine.harnesses._types import HarnessStep

#: ``modelUsage[...].provider`` -> OpenTine provider. Bedrock and Vertex keep
#: their own names: Anthropic's first-party cards must not price them.
_PROVIDERS = {"firstParty": "anthropic"}
_ENV_PROVIDERS = (
    ("CLAUDE_CODE_USE_BEDROCK", "bedrock"),
    ("CLAUDE_CODE_USE_VERTEX", "vertex"),
    ("CLAUDE_CODE_USE_FOUNDRY", "foundry"),
)
_INPUT_SIDE = {
    "input": "inputTokens",
    "cache_read": "cacheReadInputTokens",
}
MAX_TOOL_RESULT_CHARS = 64_000
#: Event types the structured stream emits; ``rate_limit_event`` and anything
#: newer are consumed silently rather than recorded as noise.
STREAM_EVENTS = frozenset({"system", "assistant", "user", "result", "rate_limit_event"})


def _count(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _money(value: Any) -> float:
    # A malformed figure from the CLI must not abort the run it describes.
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0.0
    return float(value) if math.isfinite(value) and value >= 0 else 0.0


def _input_usage(raw: Any) -> dict[str, int]:
    """The exact, input-side half of a message's usage."""
    if not isinstance(raw, Mapping):
        return {}
    creation = raw.get("cache_creation")
    creation = creation if isinstance(creation, Mapping) else {}
    write_5m = _count(creation.get("ephemeral_5m_input_tokens"))
    write_1h = _count(creation.get("ephemeral_1h_input_tokens"))
    if write_5m is None and write_1h is None:
        write_5m = _count(raw.get("cache_creation_input_tokens"))
    usage = {
        "input": _count(raw.get("input_tokens")),
        "cache_read": _count(raw.get("cache_read_input_tokens")),
        "cache_write_5m": write_5m,
        "cache_write_1h": write_1h,
    }
    return {name: value for name, value in usage.items() if value}


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(part.get("text", ""))
            for part in content
            if isinstance(part, Mapping) and part.get("type") == "text"
        )
    return ""


class ClaudeStream:
    """Per-session state: model, provider, open tool calls, input-side totals."""

    def __init__(self, env: Callable[[], Mapping[str, str]] | None = None) -> None:
        #: The environment the Claude Code subprocess actually receives: a harness
        #: forwards only an allowlist, so the parent's own variables can disagree.
        self._env = env or (lambda: os.environ)
        self.reset()

    def reset(self) -> None:
        """Start a new session: a harness object may run more than once."""
        self.model = ""
        self.provider = self._env_provider(self._env())
        self.tools: dict[str, tuple[str, Any]] = {}
        self.messages: set[str] = set()
        self.seen: dict[str, dict[str, int]] = {}

    @staticmethod
    def _env_provider(env: Mapping[str, str]) -> str:
        for name, provider in _ENV_PROVIDERS:
            if str(env.get(name, "")).strip().casefold() not in ("", "0", "false"):
                return provider
        return "anthropic"

    def step(self, data: Mapping[str, Any]) -> HarnessStep | list[HarnessStep] | None:
        kind, subtype = data.get("type"), data.get("subtype")
        if kind == "system" and subtype == "init":
            self.reset()
            self.model = str(data.get("model") or "")
            return HarnessStep(
                kind=StepKind.think,
                inputs={
                    "event": "init",
                    "session_id": data.get("session_id"),
                    "model": self.model,
                    "claude_code_version": data.get("claude_code_version"),
                    "tools": data.get("tools"),
                    "mcp_servers": data.get("mcp_servers"),
                },
                model_info=self.model or None,
            )
        if kind == "assistant":
            return self._assistant(data)
        if kind == "user":
            return self._tool_results(data) or None
        if kind == "result":
            return self._result(data)
        return None

    def _assistant(self, data: Mapping[str, Any]) -> HarnessStep:
        message = data.get("message")
        message = message if isinstance(message, Mapping) else {}
        model = str(message.get("model") or self.model)
        identifier = str(message.get("id") or "")
        # A message streamed as several events repeats its usage on each.
        usage = {} if identifier in self.messages else _input_usage(message.get("usage"))
        if identifier:
            self.messages.add(identifier)
        totals = self.seen.setdefault(model, {})
        for name, value in usage.items():
            totals[name] = totals.get(name, 0) + value
        content = message.get("content")
        blocks = [b for b in content if isinstance(b, Mapping)] if isinstance(content, list) else []
        calls = []
        for block in blocks:
            if block.get("type") == "tool_use":
                call_id, name = str(block.get("id") or ""), str(block.get("name") or "tool")
                self.tools[call_id] = (name, block.get("input"))
                calls.append({"id": call_id, "name": name, "arguments": block.get("input")})
        return HarnessStep(
            kind=StepKind.model,
            inputs={"message_id": identifier, "parent_tool_use_id": data.get("parent_tool_use_id")},
            outputs={"text": _text(blocks), "tool_calls": calls},
            model_info=model or None,
            provider=self.provider,
            usage=usage,
        )

    def _tool_results(self, data: Mapping[str, Any]) -> list[HarnessStep]:
        message = data.get("message")
        content = message.get("content") if isinstance(message, Mapping) else None
        steps = []
        for block in content if isinstance(content, list) else []:
            if not isinstance(block, Mapping) or block.get("type") != "tool_result":
                continue
            call_id = str(block.get("tool_use_id") or "")
            name, arguments = self.tools.pop(call_id, ("tool", None))
            result = _text(block.get("content"))
            steps.append(
                HarnessStep(
                    kind=StepKind.tool,
                    inputs={"name": name, "arguments": arguments, "tool_use_id": call_id},
                    outputs={
                        "result": result[:MAX_TOOL_RESULT_CHARS],
                        "truncated": len(result) > MAX_TOOL_RESULT_CHARS,
                        "is_error": bool(block.get("is_error")),
                    },
                    model_info=self.model or None,
                )
            )
        return steps

    def _result(self, data: Mapping[str, Any]) -> list[HarnessStep]:
        steps = []
        per_model = data.get("modelUsage")
        for model, totals in (per_model if isinstance(per_model, Mapping) else {}).items():
            if not isinstance(totals, Mapping):
                continue
            seen = self.seen.get(str(model), {})
            usage: dict[str, int] = {}
            output = _count(totals.get("outputTokens"))
            if output:
                usage["output"] = output
            for name, key in _INPUT_SIDE.items():
                remainder = (_count(totals.get(key)) or 0) - seen.get(name, 0)
                if remainder > 0:
                    usage[name] = remainder
            written = seen.get("cache_write_5m", 0) + seen.get("cache_write_1h", 0)
            unwritten = (_count(totals.get("cacheCreationInputTokens")) or 0) - written
            if unwritten > 0:
                usage["cache_write_5m"] = unwritten
            raw_provider = totals.get("provider")
            provider = _PROVIDERS.get(str(raw_provider), str(raw_provider or self.provider))
            inputs: dict[str, Any] = {"event": "result-usage", "model": model}
            if seen and provider != self.provider:
                # Claude Code can switch to Bedrock/Vertex from its own settings,
                # which the environment does not show: this model's per-call steps
                # were recorded under the assumed provider. Say so, never silently.
                inputs["provider_mismatch"] = {"assumed": self.provider, "reported": provider}
            steps.append(
                HarnessStep(
                    kind=StepKind.model,
                    inputs=inputs,
                    outputs={"reported_cost_usd": totals.get("costUSD")},
                    model_info=str(model),
                    provider=provider,
                    usage=usage,
                )
            )
        failed = bool(data.get("is_error"))
        steps.append(
            HarnessStep(
                kind=StepKind.error if failed else StepKind.done,
                inputs={
                    "event": "result",
                    "subtype": data.get("subtype"),
                    "num_turns": data.get("num_turns"),
                    "session_id": data.get("session_id"),
                    "reported_by": "claude-code",
                },
                outputs={"result": data.get("result")},
                # Claude Code's own list-price figure; `tine price` re-prices the
                # model steps from the signed catalog independently.
                cost=_money(data.get("total_cost_usd")),
                duration=(_count(data.get("duration_ms")) or 0) / 1000,
                model_info=self.model or None,
            )
        )
        return steps
