"""A run as a Claude Code transcript, for ``tine export --format entire``.

Entire stores each session's raw agent transcript as ``full.jsonl``; the one
agent format OpenTine both reads and can faithfully write is Claude Code's, so
an exported checkpoint names ``"agent": "Claude Code"`` and carries the run in
that shape. The mapping is the inverse of
:mod:`opentine.trace._transcript_claude`: ``human`` steps become user lines,
``model`` steps assistant lines (usage in Anthropic's exclusive buckets), and
each ``tool`` step a ``tool_use`` block on the assistant message before it plus
the user line returning its result. Importing the export back yields the same
step kinds, models and token counts. The caller redacts the run first.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


def iso(seconds: float) -> str:
    try:
        when = datetime.fromtimestamp(seconds or 0, UTC)
    except (OverflowError, OSError, ValueError):
        when = datetime.fromtimestamp(0, UTC)
    return when.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _kind(step: Any) -> str:
    return step.v3_kind or getattr(step.kind, "value", str(step.kind))


def _amount(usage: dict[str, Any], name: str) -> int:
    value = usage.get(name)
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def anthropic_usage(usage: dict[str, Any]) -> dict[str, Any]:
    """OpenTine's exclusive buckets as an Anthropic ``usage`` block."""
    reasoning = _amount(usage, "reasoning")
    out: dict[str, Any] = {
        "input_tokens": _amount(usage, "input"),
        "output_tokens": _amount(usage, "output") + reasoning,
        "cache_read_input_tokens": _amount(usage, "cache_read"),
        "cache_creation": {
            "ephemeral_5m_input_tokens": _amount(usage, "cache_write_5m"),
            "ephemeral_1h_input_tokens": _amount(usage, "cache_write_1h"),
        },
    }
    if reasoning:
        out["output_tokens_details"] = {"thinking_tokens": reasoning}
    return out


def _text(payload: Any, *keys: str) -> str:
    payload = payload if isinstance(payload, dict) else {}
    for key in keys:
        if isinstance(payload.get(key), str):
            return payload[key]
    return ""


class _Writer:
    def __init__(self, session_id: str, cwd: str) -> None:
        self.base = {"sessionId": session_id, "cwd": cwd, "version": "opentine-export"}
        self.lines: list[dict[str, Any]] = []
        self.assistant: dict[str, Any] | None = None

    def add(self, kind: str, step: Any, message: dict[str, Any]) -> dict[str, Any]:
        parent = self.lines[-1]["uuid"] if self.lines else None
        line = {
            **self.base,
            "type": kind,
            "uuid": f"{kind[0]}-{step.id[:24]}-{len(self.lines)}",
            "parentUuid": parent,
            "timestamp": iso(step.timestamp),
            "message": message,
        }
        self.lines.append(line)
        return line

    def model(self, step: Any, model: str) -> None:
        outputs = step.outputs or {}
        content: list[dict[str, Any]] = []
        if text := _text(outputs, "text", "content", "result"):
            content.append({"type": "text", "text": text})
        message = {
            "id": f"msg_{step.id[:24]}",
            "type": "message",
            "role": "assistant",
            "model": step.model_info or model,
            "content": content,
            "usage": anthropic_usage(step.usage or {}),
        }
        self.assistant = self.add("assistant", step, message)
        self.assistant["requestId"] = f"req_{step.id[:24]}"

    def tool(self, step: Any, model: str) -> None:
        inputs, outputs = step.inputs or {}, step.outputs or {}
        if self.assistant is None:  # a tool call with no model step before it
            self.model(step, model)
        owner: dict[str, Any] = self.assistant or {}
        call = f"toolu_{step.id[:24]}"
        arguments = inputs.get("arguments")
        owner["message"]["content"].append(
            {
                "type": "tool_use",
                "id": call,
                "name": str(inputs.get("name") or step.tool_info.get("name") or "tool"),
                "input": arguments if isinstance(arguments, dict) else {"input": arguments},
            }
        )
        result = outputs.get("result", outputs.get("output", outputs))
        block = {
            "type": "tool_result",
            "tool_use_id": call,
            "content": result if isinstance(result, str) else json.dumps(result, default=str),
            "is_error": bool(outputs.get("is_error")),
        }
        self.add("user", step, {"role": "user", "content": [block]})

    def human(self, step: Any) -> None:
        text = _text(step.inputs, "text", "prompt", "content")
        self.assistant = None
        self.add("user", step, {"role": "user", "content": text})


def claude_lines(run: Any, session_id: str, cwd: str = "") -> list[dict[str, Any]]:
    """Every step of *run* as Claude Code transcript records, in order."""
    writer = _Writer(session_id, cwd)
    model = str(run.model_info or "")
    for step in run.steps:
        kind = _kind(step)
        if kind == "human":
            writer.human(step)
        elif kind == "tool":
            writer.tool(step, model)
        elif kind == "model":
            writer.model(step, model)
    return writer.lines


def first_prompt(run: Any) -> str:
    for step in run.steps:
        if _kind(step) == "human":
            return _text(step.inputs, "text", "prompt", "content")
    return ""


__all__ = ["anthropic_usage", "claude_lines", "first_prompt", "iso"]
