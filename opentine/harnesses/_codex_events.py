"""Codex ``exec --json`` events -> priceable harness steps.

Built from Codex's own event definitions (``codex-rs/exec/src/exec_events.rs`` and
``event_processor_with_jsonl_output.rs``, openai/codex main, fetched 2026-10-15),
not guessed. Two details decide whether a run prices correctly:

* ``turn.completed.usage`` is the *thread's running total*
  (``usage_from_last_total``), not the turn's: a resumed thread's second turn
  reports both turns. Each model step records the difference from the previous
  total.
* The counts follow OpenAI's convention: ``input_tokens`` includes
  ``cached_input_tokens`` and ``cache_write_input_tokens``; ``output_tokens``
  includes ``reasoning_output_tokens``. OpenTine's buckets are exclusive, so they
  are split here exactly as :func:`opentine.models._usage.openai_usage` does.

No event names the model. It comes from ``-m``/``--model``/``-c model=...`` on the
command, else ``model`` in ``$CODEX_HOME/config.toml``; a ``model rerouted: a -> b``
error item updates it. ``--oss`` / ``--local-provider`` / ``model_provider`` name
who served it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from opentine.core import StepKind
from opentine.harnesses._types import MAX_COUNT, HarnessStep

CODEX_EVENTS = frozenset(
    {
        "thread.started",
        "turn.started",
        "turn.completed",
        "turn.failed",
        "item.started",
        "item.updated",
        "item.completed",
        "error",
    }
)
MAX_RESULT_CHARS = 64_000
_REROUTE = re.compile(r"model rerouted: (\S+) -> (\S+)")
_USAGE_KEYS = (
    "input_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)


def _count(value: Any) -> int:
    # Bounded like every other usage reader: a total past 2**53 made the step
    # unrecordable and ended the run (final pass 6, #9).
    return value if type(value) is int and 0 <= value <= MAX_COUNT else 0


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_RESULT_CHARS:
        return value[:MAX_RESULT_CHARS]
    return value


def split_usage(totals: Mapping[str, int]) -> dict[str, int]:
    """OpenAI-convention counts -> OpenTine's exclusive buckets (zeros dropped)."""
    cached = totals.get("cached_input_tokens", 0)
    written = totals.get("cache_write_input_tokens", 0)
    reasoning = totals.get("reasoning_output_tokens", 0)
    usage = {
        "input": max(totals.get("input_tokens", 0) - cached - written, 0),
        "cache_read": cached,
        "cache_write_5m": written,
        "output": max(totals.get("output_tokens", 0) - reasoning, 0),
        "reasoning": reasoning,
    }
    return {name: count for name, count in usage.items() if count}


class CodexStream:
    """Per-session state: model, provider, and the last running usage total."""

    def __init__(self, model: str, provider: str) -> None:
        self.model, self.provider = model, provider
        self.totals = dict.fromkeys(_USAGE_KEYS, 0)
        self.thread_id = ""

    def step(self, data: Mapping[str, Any]) -> HarnessStep | None:
        kind = data.get("type")
        if kind == "thread.started":
            self.thread_id = str(data.get("thread_id") or "")
            return self._step(StepKind.think, {"event": kind, "thread_id": self.thread_id})
        if kind == "turn.completed":
            return self._turn_usage(data.get("usage"))
        if kind in ("turn.failed", "error"):
            error = data.get("error") if kind == "turn.failed" else data
            message = error.get("message") if isinstance(error, Mapping) else error
            return self._step(StepKind.error, {"event": kind, "error": str(message or "")})
        if kind == "item.completed":
            item = data.get("item")
            return self._item(item) if isinstance(item, Mapping) else None
        return None  # turn.started, item.started/updated: the completed item says it all

    def _step(self, kind: StepKind, inputs: dict[str, Any], **extra: Any) -> HarnessStep:
        if self.thread_id:
            inputs.setdefault("thread_id", self.thread_id)
        return HarnessStep(kind=kind, inputs=inputs, model_info=self.model or None, **extra)

    def _turn_usage(self, raw: Any) -> HarnessStep:
        current = (
            {key: _count(raw.get(key)) for key in _USAGE_KEYS} if isinstance(raw, Mapping) else {}
        )
        delta = {key: max(current.get(key, 0) - self.totals[key], 0) for key in _USAGE_KEYS}
        if current:
            self.totals = {key: max(current.get(key, 0), self.totals[key]) for key in _USAGE_KEYS}
        return self._step(
            StepKind.model,
            {"event": "turn.completed", "model": self.model},
            usage=split_usage(delta),
            provider=self.provider,
        )

    def _item(self, item: Mapping[str, Any]) -> HarnessStep | None:
        kind, item_id = item.get("type"), str(item.get("id") or "")
        if kind in ("agent_message", "reasoning"):
            text = str(item.get("text") or "")
            return self._step(StepKind.think, {"event": kind, "item_id": item_id, "text": text})
        if kind == "todo_list":
            return self._step(StepKind.think, {"event": kind, "items": item.get("items")})
        if kind == "error":
            message = str(item.get("message") or "")
            if rerouted := _REROUTE.search(message):
                self.model = rerouted.group(2)
            return self._step(StepKind.error, {"event": kind, "error": message})
        tool = _tool(kind, item)
        if tool is None:
            return None
        name, arguments, result = tool
        return self._step(
            StepKind.tool,
            {"name": name, "arguments": arguments, "item_id": item_id},
            outputs={"result": _clip(result), "status": item.get("status")},
        )


def _tool(kind: Any, item: Mapping[str, Any]) -> tuple[str, Any, Any] | None:
    if kind == "command_execution":
        result = {"output": item.get("aggregated_output"), "exit_code": item.get("exit_code")}
        return "shell", {"command": item.get("command")}, result
    if kind == "file_change":
        return "apply_patch", {"changes": item.get("changes")}, None
    if kind == "mcp_tool_call":
        name = f"{item.get('server') or 'mcp'}.{item.get('tool') or 'tool'}"
        arguments = {"server": item.get("server"), "arguments": item.get("arguments")}
        return name, arguments, item.get("error") or item.get("result")
    if kind == "web_search":
        return "web_search", {"query": item.get("query")}, item.get("results")
    if kind == "collab_tool_call":
        arguments = {"prompt": item.get("prompt"), "receivers": item.get("receiver_thread_ids")}
        return f"collab.{item.get('tool') or 'tool'}", arguments, item.get("agents_states")
    return None


def command_model(command: tuple[str, ...]) -> tuple[str, str, str]:
    """``(model, provider, profile)`` named on a Codex command line (last wins)."""
    model = provider = profile = ""
    oss = False
    for index, token in enumerate(command):
        following = command[index + 1] if index + 1 < len(command) else ""
        name, _, inline = token.partition("=")
        value = inline if inline and name.startswith("--") else following
        if token in ("-m", "--model") or name == "--model":
            model = value
        elif token in ("-c", "--config") and "=" in following:
            key, _, setting = following.partition("=")
            setting = setting.strip().strip("\"'")
            if key.strip() == "model":
                model = setting
            elif key.strip() == "model_provider":
                provider = setting
        elif token == "--local-provider" or name == "--local-provider":
            provider, oss = value, True
        elif token == "--oss":
            oss = True
        elif token in ("-p", "--profile") or name == "--profile":
            profile = value
    if oss and not provider:
        provider = "oss"
    return model, provider, profile
