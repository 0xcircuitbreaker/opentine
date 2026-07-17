"""Bounded parsing for provider responses that mix text and structured blocks."""

from __future__ import annotations

from typing import Any

from opentine.models._chat_blocks import parse_chat_blocks
from opentine.models._continuation import anthropic_blocks, google_blocks
from opentine.models._streaming import (
    MAX_STREAM_CALLS,
    SizeBudget,
    TextBuffer,
    WarningList,
)
from opentine.models._terminal import reject_unsafe_tool_calls
from opentine.models._tool_args import bounded_tool_arguments
from opentine.models._usage import value

MAX_STREAM_BLOCKS = 1024


def _identifier(raw: Any) -> str | None:
    if raw is None:
        return None
    return str(raw)[:4096] or None


def chat_content(message: Any) -> dict[str, Any]:
    """Parse a complete Chat Completions message within retention limits."""
    warnings: list[str] = WarningList()
    text = TextBuffer("Chat text")
    refusal = TextBuffer("Chat refusal")
    reasoning = TextBuffer("Chat reasoning")
    arguments = SizeBudget()
    calls: list[dict[str, Any]] = []
    body, thought, content_blocks, block_warnings = parse_chat_blocks(
        value(message, "content", "") or ""
    )
    warnings.extend(block_warnings)
    text.add(body)
    refusal.add(value(message, "refusal", "") or "")
    reasoning.add(value(message, "reasoning_content") or value(message, "reasoning") or thought)
    raw_calls = value(message, "tool_calls", []) or []
    for call in raw_calls[:MAX_STREAM_CALLS]:
        function = value(call, "function")
        raw = value(function, "arguments", {})
        kept = bounded_tool_arguments(raw, arguments, warnings, "Chat", value(function, "name", ""))
        calls.append(
            {
                "name": str(value(function, "name", ""))[:4096],
                "arguments": kept,
                "id": _identifier(value(call, "id")),
            }
        )
    if len(raw_calls) > MAX_STREAM_CALLS:
        warnings.append(f"streamed tool calls truncated at {MAX_STREAM_CALLS} entries")
    for buffer in (text, refusal, reasoning):
        buffer.warn(warnings)
    result: dict[str, Any] = {"text": text.text, "tool_calls": calls, "warnings": warnings}
    if refusal.text:
        result["refusal"] = refusal.text
    if reasoning.text:
        result["reasoning_content"] = reasoning.text
    if content_blocks is not None:
        result["content_blocks"] = content_blocks
    reject_unsafe_tool_calls(result)
    return result


def _blocks(raw: Any, warnings: list[str], label: str):
    values = raw or []
    for index, block in enumerate(values):
        if index >= MAX_STREAM_BLOCKS:
            warnings.append(f"streamed {label} truncated at {MAX_STREAM_BLOCKS} blocks")
            break
        yield block


def anthropic_content(response: Any) -> dict[str, Any]:
    warnings: list[str] = WarningList()
    text = TextBuffer("Anthropic text")
    reasoning = TextBuffer("Anthropic reasoning")
    refusal = TextBuffer("Anthropic refusal")
    calls: list[dict[str, Any]] = []
    arguments = SizeBudget()
    raw_content = value(response, "content")
    for block in _blocks(raw_content, warnings, "Anthropic content"):
        block_type = value(block, "type")
        if block_type == "text":
            text.add(value(block, "text"))
        elif block_type in {"thinking", "reasoning"}:
            reasoning.add(value(block, "thinking", value(block, "text", "")))
        elif block_type == "refusal":
            refusal.add(value(block, "refusal", value(block, "text", "")))
        elif block_type == "tool_use":
            if len(calls) >= MAX_STREAM_CALLS:
                warnings.append(f"streamed tool calls truncated at {MAX_STREAM_CALLS} entries")
                continue
            calls.append(
                {
                    "name": str(value(block, "name", ""))[:4096],
                    "arguments": bounded_tool_arguments(
                        value(block, "input", {}),
                        arguments,
                        warnings,
                        "Anthropic",
                        value(block, "name", ""),
                    ),
                    "id": _identifier(value(block, "id")),
                }
            )
    for buffer in (text, reasoning, refusal):
        buffer.warn(warnings)
    result: dict[str, Any] = {
        "text": text.text,
        "tool_calls": calls,
        "warnings": warnings,
    }
    if reasoning.text:
        result["reasoning_content"] = reasoning.text
    if refusal.text:
        result["refusal"] = refusal.text
    continuation = anthropic_blocks(raw_content, warnings)
    if continuation:
        result["anthropic_content"] = continuation
    reject_unsafe_tool_calls(result)
    return result


def google_content(response: Any, argument_budget: SizeBudget | None = None) -> dict[str, Any]:
    warnings: list[str] = WarningList()
    text = TextBuffer("Google text")
    reasoning = TextBuffer("Google reasoning")
    calls: list[dict[str, Any]] = []
    argument_budget = argument_budget or SizeBudget()
    candidates = value(response, "candidates", []) or []
    candidate = candidates[0] if candidates else None
    content = value(candidate, "content")
    raw_parts = value(content, "parts")
    for part in _blocks(raw_parts, warnings, "Google content"):
        part_text = value(part, "text", "") or ""
        (reasoning if value(part, "thought", False) else text).add(part_text)
        function = value(part, "function_call")
        if function and len(calls) < MAX_STREAM_CALLS:
            arguments = bounded_tool_arguments(
                value(function, "args", {}),
                argument_budget,
                warnings,
                "Google",
                value(function, "name", ""),
            )
            calls.append(
                {
                    "name": str(value(function, "name", ""))[:4096],
                    "arguments": arguments,
                    "id": _identifier(value(function, "id")),
                }
            )
        elif function:
            warnings.append(f"streamed tool calls truncated at {MAX_STREAM_CALLS} entries")
    if not text.text:
        try:
            fallback = response.text or ""
        except (AttributeError, ValueError):
            fallback = ""
        if fallback and not reasoning.text:
            text.add(fallback)
    blocked = value(value(response, "prompt_feedback"), "block_reason")
    if not blocked and candidate:
        finish = value(candidate, "finish_reason")
        if finish and str(finish).split(".")[-1] != "STOP":
            blocked = finish
    for buffer in (text, reasoning):
        buffer.warn(warnings)
    result = {
        "text": text.text,
        "tool_calls": calls,
        "warnings": warnings,
    }
    if reasoning.text:
        result["reasoning_content"] = reasoning.text
    if blocked:
        result["refusal"] = str(blocked)[:4096]
    continuation = google_blocks(raw_parts, warnings)
    if continuation:
        result["google_content"] = continuation
    reject_unsafe_tool_calls(result)
    return result


class OllamaStreamState:
    def __init__(self, warnings: list[str]) -> None:
        self.warnings = warnings
        self.text = TextBuffer("Ollama aggregate text")
        self.thinking = TextBuffer("Ollama aggregate thinking")
        self.refusal = TextBuffer("Ollama refusal")
        self.calls: list[dict[str, Any]] = []
        self.arguments = SizeBudget()

    def add(self, message: dict[str, Any]) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        for field, buffer, event_type in (
            ("thinking", self.thinking, "thinking_delta"),
            ("content", self.text, "text_delta"),
            ("refusal", self.refusal, "refusal_delta"),
        ):
            delta = buffer.add(message.get(field, ""))
            if delta:
                events.append({"type": event_type, "text": delta})
        for call in message.get("tool_calls", []) or []:
            if len(self.calls) >= MAX_STREAM_CALLS:
                self.warnings.append(f"streamed tool calls truncated at {MAX_STREAM_CALLS} entries")
                break
            function = dict(call.get("function", {}))
            function["arguments"] = bounded_tool_arguments(
                function.get("arguments", {}),
                self.arguments,
                self.warnings,
                "Ollama",
                function.get("name", ""),
            )
            self.calls.append({**call, "function": function})
        return events

    def message(self) -> dict[str, Any]:
        for buffer in (self.text, self.thinking, self.refusal):
            buffer.warn(self.warnings)
        return {
            "content": self.text.text,
            "thinking": self.thinking.text,
            "tool_calls": self.calls,
            "refusal": self.refusal.text,
        }
