"""Event-stream dialects: Gemini CLI and Hermes Agent.

Each was read off the CLI's own source or reference docs (fixtures under
``tests/fixtures/harness/`` name the source and date):

* Gemini CLI ``--output-format stream-json`` (``packages/core/src/output/types.ts``):
  ``init`` names the model; ``result.stats.models`` carries per-model
  ``input_tokens`` (= prompt, *including* ``cached``), ``output_tokens``
  (= candidates, *excluding* thoughts) and ``total_tokens`` (which includes
  thoughts) -- so reasoning is ``total - input_tokens - output_tokens``.
* Hermes ``chat --format stream-json``: ``result.tokens`` is Hermes'
  ``CanonicalUsage`` -- ``input`` excludes cache reads/writes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentine.harnesses._dialect_base import (
    count,
    done_step,
    error_step,
    model_step,
    think_step,
    tool_step,
    usage,
)
from opentine.harnesses._dialect_harness import Dialect
from opentine.harnesses._types import HarnessStep


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


class _Buffered(Dialect):
    """Coalesces streamed assistant text deltas into one think step."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.text: list[str] = []
        self.tools: dict[str, tuple[str, Any]] = {}

    def flush(self) -> list[HarnessStep]:
        text, self.text = "".join(self.text), []
        return [think_step(text, self.model)] if text.strip() else []


class Gemini(_Buffered):
    cli = "gemini"
    default_provider = "google"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        vertex = str(self.env.get("GOOGLE_GENAI_USE_VERTEXAI", "")).lower() in ("1", "true")
        if vertex and self.provider == "google":
            self.provider = "vertex"

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        kind = data.get("type")
        if kind == "init":
            self.set_model(data.get("model"))
            return [think_step("", self.model, event="init", session_id=data.get("session_id"))]
        if kind == "message":
            if data.get("role") == "assistant":
                self.text.append(str(data.get("content") or ""))
            return []
        if kind == "tool_use":
            self.tools[str(data.get("tool_id"))] = (
                str(data.get("tool_name")),
                data.get("parameters"),
            )
            return self.flush()
        if kind == "tool_result":
            name, arguments = self.tools.pop(str(data.get("tool_id")), ("tool", None))
            error = _map(data.get("error"))
            result = data.get("output") if data.get("output") is not None else error.get("message")
            return [
                *self.flush(),
                tool_step(
                    name,
                    arguments,
                    result,
                    self.model,
                    error=data.get("status") == "error",
                    tool_use_id=data.get("tool_id"),
                ),
            ]
        if kind == "error":
            severe = data.get("severity") == "error"
            step = error_step if severe else think_step
            return [*self.flush(), step(data.get("message"), self.model)]
        if kind == "result":
            return [*self.flush(), *self._result(data)]
        return None

    def _result(self, data: Mapping[str, Any]) -> list[HarnessStep]:
        steps = []
        for model, stats in _map(_map(data.get("stats")).get("models")).items():
            stats = _map(stats)
            prompt, output = count(stats.get("input_tokens")), count(stats.get("output_tokens"))
            thoughts = max(count(stats.get("total_tokens")) - prompt - output, 0)
            tokens = usage(
                input=prompt,
                output=output,
                cache_read=stats.get("cached"),
                reasoning=thoughts,
                input_includes_cache=True,
            )
            steps.append(model_step(str(model), self.provider, tokens, event="result-usage"))
        error = _map(data.get("error"))
        failed = data.get("status") == "error"
        steps.append(
            done_step(
                error.get("message") if failed else "",
                self.cli,
                self.model,
                failed=failed,
                duration_ms=_map(data.get("stats")).get("duration_ms"),
            )
        )
        return steps


class Hermes(_Buffered):
    cli = "hermes"

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        kind = data.get("type")
        if kind == "system":
            self.set_model(data.get("model"))
            return [
                think_step(
                    "", self.model, event=data.get("subtype"), session_id=data.get("session_id")
                )
            ]
        if kind == "text":
            self.text.append(str(data.get("text") or ""))
            return []
        if kind == "tool_use":
            self.tools[str(data.get("name"))] = (str(data.get("name")), data.get("input"))
            return self.flush()
        if kind == "tool_result":
            name, arguments = self.tools.pop(
                str(data.get("name")), (str(data.get("name") or "tool"), None)
            )
            return [
                *self.flush(),
                tool_step(
                    name,
                    arguments,
                    data.get("output"),
                    self.model,
                    error=bool(data.get("is_error")),
                ),
            ]
        if kind == "result":
            raw = _map(data.get("tokens"))
            tokens = usage(
                input=raw.get("input"),
                output=raw.get("output"),
                cache_read=raw.get("cache_read"),
                cache_write=raw.get("cache_write"),
            )
            failed = bool(data.get("error")) or count(data.get("exit_code")) != 0
            steps = self.flush()
            if tokens:
                steps.append(model_step(self.model, self.provider, tokens, event="result-usage"))
            steps.append(
                done_step(
                    data.get("error") if failed else data.get("text"),
                    self.cli,
                    self.model,
                    failed=failed,
                    exit_code=data.get("exit_code"),
                )
            )
            return steps
        return None


__all__ = ["Gemini", "Hermes"]
