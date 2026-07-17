"""Small, provider-neutral accumulators for streamed response fidelity."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from opentine.models._usage import value

MAX_STREAM_CHARS = 1024 * 1024
MAX_STREAM_CALLS = 256
MAX_STREAM_WARNINGS = 64


class WarningList(list[str]):
    """A deduplicating warning list with a hard retained-memory count cap."""

    def append(self, item: str) -> None:
        if len(self) < MAX_STREAM_WARNINGS and item not in self:
            super().append(item)

    def extend(self, values) -> None:
        for item in values:
            self.append(item)


class SizeBudget:
    """Bound the aggregate retained size of structured provider values."""

    def __init__(self, limit: int | None = None) -> None:
        self.remaining = MAX_STREAM_CHARS if limit is None else limit

    def keep(self, value: Any, warnings: list[str], label: str) -> Any:
        remaining = _fits(value, self.remaining)
        if remaining >= 0:
            self.remaining = remaining
            return value
        warnings.append(f"streamed {label} exceeded its aggregate safe size and was discarded")
        return {"_truncated": True}


def chat_chunk_usage(chunk: Any, choices: list[Any]) -> Any:
    """Accept top-level usage and Kimi's final per-choice stream usage."""
    raw = value(chunk, "usage")
    return value(choices[0], "usage") if raw is None and choices else raw


class TextBuffer:
    """Retain a bounded prefix while allowing the original delta to pass through."""

    def __init__(self, label: str, limit: int | None = None) -> None:
        self.label = label
        self.limit = MAX_STREAM_CHARS if limit is None else limit
        self.parts: list[str] = []
        self.size = 0
        self.truncated = False

    def add(self, value: Any) -> str:
        text = value if isinstance(value, str) else ""
        remaining = max(0, self.limit - self.size)
        if text and remaining:
            kept = text[:remaining]
            self.parts.append(kept)
            self.size += len(kept)
        if len(text) > remaining:
            self.truncated = True
        return text

    @property
    def text(self) -> str:
        return "".join(self.parts)

    def warn(self, warnings: list[str]) -> None:
        if self.truncated:
            warning = f"streamed {self.label} truncated at {self.limit} characters"
            if warning not in warnings:
                warnings.append(warning)


def _fits(value: Any, remaining: int, depth: int = 0) -> int:
    if remaining < 0 or depth > 32:
        return -1
    if value is None or isinstance(value, (bool, int, float)):
        return remaining - 32
    if isinstance(value, (str, bytes, bytearray)):
        return remaining - len(value)
    if isinstance(value, Mapping):
        if len(value) > 4096:
            return -1
        for key, item in value.items():
            remaining = _fits(key, remaining, depth + 1)
            remaining = _fits(item, remaining, depth + 1)
            if remaining < 0:
                return -1
        return remaining
    if isinstance(value, Sequence):
        if len(value) > 4096:
            return -1
        for item in value:
            remaining = _fits(item, remaining, depth + 1)
            if remaining < 0:
                return -1
        return remaining
    return -1


class ChatStreamState:
    """Reassemble Chat Completions deltas without losing non-text output."""

    def __init__(self) -> None:
        self.text = TextBuffer("text")
        self.reasoning = TextBuffer("reasoning")
        self.refusals = TextBuffer("refusal")
        self.calls: dict[int, dict[str, Any]] = {}
        self.warnings: list[str] = WarningList()
        self.argument_budget = SizeBudget()

    def add(self, delta: Any) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        text = self.text.add(value(delta, "content"))
        if text:
            events.append({"type": "text_delta", "text": text})
        refusal = self.refusals.add(value(delta, "refusal"))
        if refusal:
            events.append({"type": "refusal_delta", "text": refusal})
        reasoning = self.reasoning.add(value(delta, "reasoning_content"))
        if reasoning:
            events.append({"type": "reasoning_delta", "text": reasoning})
        for position, call in enumerate(value(delta, "tool_calls", []) or []):
            raw_index = value(call, "index", position)
            index = raw_index if type(raw_index) is int and raw_index >= 0 else position
            if index not in self.calls and len(self.calls) >= MAX_STREAM_CALLS:
                warning = f"streamed tool calls truncated at {MAX_STREAM_CALLS} entries"
                if warning not in self.warnings:
                    self.warnings.append(warning)
                continue
            current = self.calls.setdefault(
                index,
                {
                    "arguments": TextBuffer(f"tool call {index} arguments"),
                    "id": None,
                    "name": TextBuffer(f"tool call {index} name", 4096),
                },
            )
            call_id = value(call, "id")
            if isinstance(call_id, str) and call_id:
                current["id"] = call_id[:4096]
                if len(call_id) > 4096:
                    self.warnings.append("streamed tool call id truncated at 4096 characters")
            function = value(call, "function")
            current["name"].add(value(function, "name"))
            arguments = value(function, "arguments")
            if isinstance(arguments, str):
                safe = self.argument_budget.keep(arguments, self.warnings, "Chat tool arguments")
                if isinstance(safe, str):
                    current["arguments"].add(safe)
                else:
                    current["arguments"].truncated = True
            elif arguments is not None:
                safe = self.argument_budget.keep(arguments, self.warnings, "Chat tool arguments")
                current["arguments"].add(json.dumps(safe, separators=(",", ":")))
        return events

    def result(self) -> dict[str, Any]:
        calls: list[dict[str, Any]] = []
        warnings: list[str] = WarningList()
        warnings.extend(self.warnings)
        for buffer in (self.text, self.reasoning, self.refusals):
            buffer.warn(warnings)
        for call in (self.calls[index] for index in sorted(self.calls)):
            name, arguments = call["name"], call["arguments"]
            name.warn(warnings)
            arguments.warn(warnings)
            if arguments.truncated:
                parsed = {"_truncated": True}
            else:
                try:
                    parsed = json.loads(arguments.text or "{}")
                except json.JSONDecodeError:
                    parsed = {"_raw": arguments.text}
                    warnings.append(f"invalid JSON arguments for {name.text}")
            calls.append({"name": name.text, "arguments": parsed, "id": call["id"]})
        result: dict[str, Any] = {
            "text": self.text.text,
            "tool_calls": calls,
            "warnings": warnings,
        }
        if self.refusals.text:
            result["refusal"] = self.refusals.text
        if self.reasoning.text:
            result["reasoning_content"] = self.reasoning.text
        return result


def ollama_result(data: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    """Normalize a complete or reassembled Ollama message."""
    message = data.get("message", {})
    calls = []
    arguments = SizeBudget()
    for call in (message.get("tool_calls", []) or [])[:MAX_STREAM_CALLS]:
        function = call.get("function", {})
        calls.append(
            {
                "name": function.get("name", ""),
                "arguments": arguments.keep(
                    function.get("arguments", {}), warnings, "Ollama tool arguments"
                ),
                "id": call.get("id"),
            }
        )
    if len(message.get("tool_calls", []) or []) > MAX_STREAM_CALLS:
        warnings.append(f"streamed tool calls truncated at {MAX_STREAM_CALLS} entries")
    text, thinking, refusal = (TextBuffer(name) for name in ("text", "thinking", "refusal"))
    text.add(message.get("content", ""))
    thinking.add(message.get("thinking", ""))
    refusal.add(message.get("refusal", ""))
    for buffer in (text, thinking, refusal):
        buffer.warn(warnings)
    result: dict[str, Any] = {
        "text": text.text,
        "thinking": thinking.text,
        "tool_calls": calls,
        "warnings": warnings,
        "metrics": {
            key: data[key]
            for key in (
                "total_duration",
                "load_duration",
                "prompt_eval_count",
                "prompt_eval_duration",
                "eval_count",
                "eval_duration",
            )
            if key in data
        },
    }
    if refusal.text:
        result["refusal"] = refusal.text
    return result
