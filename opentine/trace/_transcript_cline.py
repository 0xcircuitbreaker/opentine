"""Import a Cline or Roo Code task (``--format cline-task`` / ``roo-task``).

The task's ``api_conversation_history.json`` (see
:mod:`opentine.trace._cline_task_read`) is the conversation the model saw:
each ``assistant`` message is one model step, a ``user`` message is the
human's prompt or feedback, and the tool results the extension sent back are
tool steps. Two tool conventions are read: native ``tool_use``/``tool_result``
blocks, and the XML-tool convention both extensions started with, where a
result is a user text block opening ``[read_file for 'x'] Result:``.
``<environment_details>`` blocks the extension appends to every user turn are
dropped from the step's text and counted instead.

Usage comes from ``ui_messages.json``: the *n*-th ``api_req_started`` record
belongs to the *n*-th assistant message, its JSON text carrying ``tokensIn``,
``tokensOut``, ``cacheWrites``, ``cacheReads`` and ``cost``. With
``apiProtocol: "openai"`` ``tokensIn`` includes cache reads; otherwise it is
Anthropic's exclusive count. The model is the message's ``modelInfo`` (newer
Cline) or the latest ``task_metadata.json`` ``model_usage`` entry not after it.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from typing import Any

from opentine.trace._cline_task_read import read_task
from opentine.trace._transcript_common import (
    Chain,
    count,
    inclusive_usage,
    label,
    session_trace_id,
    text_of,
)
from opentine.trace.schema import TraceEvent

_RESULT = re.compile(r"^\[(?P<desc>[^\]\n]{1,512})\] Result:\s*", re.S)
_ENV = re.compile(r"^\s*<environment_details>.*</environment_details>\s*$", re.S)


def _requests(ui: list[Any]) -> list[dict[str, Any]]:
    found = []
    for record in ui:
        if not isinstance(record, dict) or record.get("say") != "api_req_started":
            continue
        try:
            info = json.loads(record.get("text") or "{}")
        except (ValueError, RecursionError, TypeError):
            info = {}
        found.append({"ts": record.get("ts"), **(info if isinstance(info, dict) else {})})
    return found


def _seconds(ms: Any) -> Any:
    """Both extensions stamp ``ts`` in epoch milliseconds."""
    numeric = isinstance(ms, (int, float)) and not isinstance(ms, bool)
    return ms / 1000 if numeric and ms > 0 else None


def usage_of(info: dict[str, Any], metrics: Any = None) -> dict[str, int]:
    """One request's buckets: ``api_req_started``, else the message's ``metrics``."""
    tokens = metrics.get("tokens") if isinstance(metrics, dict) else None
    if not any(key in info for key in ("tokensIn", "tokensOut")) and isinstance(tokens, dict):
        return inclusive_usage(
            tokens.get("prompt"), tokens.get("cached"), tokens.get("completion"), 0
        )
    read, write = count(info.get("cacheReads")) or 0, count(info.get("cacheWrites")) or 0
    if info.get("apiProtocol") == "openai":
        return inclusive_usage(info.get("tokensIn"), read, info.get("tokensOut"), 0, write)
    found = {
        "input": count(info.get("tokensIn")),
        "output": count(info.get("tokensOut")),
        "cache_read": read,
        "cache_write_5m": write,
    }
    return {name: value for name, value in found.items() if value}


def _model(message: dict[str, Any], when: Any, metadata: dict[str, Any]) -> tuple[str, str]:
    info = message.get("modelInfo")
    if isinstance(info, dict) and isinstance(info.get("modelId"), str):
        return info["modelId"], str(info.get("providerId") or "")
    usage = [u for u in metadata.get("model_usage") or [] if isinstance(u, dict)]
    earlier = [u for u in usage if not isinstance(when, int) or (count(u.get("ts")) or 0) <= when]
    pick = (earlier or usage or [{}])[-1]
    return str(pick.get("model_id") or ""), str(pick.get("model_provider_id") or "")


class _Builder:
    def __init__(self, task_id: str, source_format: str, metadata: dict[str, Any]) -> None:
        self.chain = Chain(session_trace_id(task_id))
        self.flags = {"source": source_format}
        self.metadata = metadata
        self.names: dict[str, str] = {}
        self.dropped = 0
        self.when: Any = None

    def assistant(self, message: dict[str, Any], info: dict[str, Any]) -> None:
        self.when = info.get("ts", message.get("ts", self.when))
        content = message.get("content")
        blocks = content if isinstance(content, list) else [{"type": "text", "text": content}]
        texts, calls = [], []
        for block in blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(str(block.get("text") or ""))
            elif isinstance(block, dict) and block.get("type") == "tool_use":
                calls.append({k: block.get(k) for k in ("id", "name", "input")})
                self.names[str(block.get("id") or "")] = label(block.get("name") or "tool")
        outputs: dict[str, Any] = {"text": "".join(texts)}
        if calls:
            outputs["tool_calls"] = calls
        attributes = dict(self.flags)
        if isinstance(info.get("cost"), (int, float)):
            attributes["reported_cost_usd"] = info["cost"]
        model, provider = _model(message, self.when, self.metadata)
        self.chain.add(
            "model",
            _seconds(self.when),
            f"message:{len(self.chain.events)}",
            actor="assistant",
            model=label(model),
            provider=label(provider)[:64],
            outputs=outputs,
            usage=usage_of(info, message.get("metrics")),
            attributes=attributes,
        )

    def _tool(self, name: str, inputs: dict[str, Any], result: Any, error: bool) -> None:
        outputs = {"result": result, "is_error": error}
        span = f"tool:{inputs.get('tool_use_id') or len(self.chain.events)}"
        self.chain.add(
            "tool",
            _seconds(self.when),
            span,
            actor=name,
            inputs=inputs,
            outputs=outputs,
            attributes=self.flags,
        )

    def user(self, message: dict[str, Any]) -> None:
        self.when = message.get("ts", self.when)
        content = message.get("content")
        blocks = content if isinstance(content, list) else [{"type": "text", "text": content}]
        texts: list[str] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_result":
                call = str(block.get("tool_use_id") or "")
                name = self.names.get(call, "tool")
                inputs = {"name": name, "tool_use_id": call}
                result = text_of(block.get("content"))
                self._tool(name, inputs, result, bool(block.get("is_error")))
            elif block.get("type") == "text" and isinstance(block.get("text"), str):
                if _ENV.match(block["text"]):
                    self.dropped += 1
                else:
                    texts.append(block["text"])
        result = _RESULT.match(texts[0]) if texts else None
        if result:
            desc = result.group("desc")
            rest = "\n".join([texts[0][result.end() :], *texts[1:]]).strip()
            name = label(desc.split(" ", 1)[0])
            self._tool(name, {"name": name, "description": desc}, rest, False)
        elif texts:
            self.chain.add(
                "human",
                _seconds(self.when),
                f"user:{len(self.chain.events)}",
                actor="user",
                inputs={"text": "\n".join(texts)},
                attributes=self.flags,
            )


def cline_events(source: Any, source_format: str = "cline-task") -> list[TraceEvent]:
    """The task at *source* as events (a directory, its history file, or lines)."""
    task = read_task(source)
    builder = _Builder(task.task_id, source_format, task.metadata)
    requests = iter(_requests(task.ui))
    for message in task.history[:100_000]:
        if not isinstance(message, dict):
            continue
        if message.get("type") == "reasoning":  # Roo's stored reasoning item, no request
            continue
        if message.get("role") == "assistant":
            builder.assistant(message, next(requests, {}))
        elif message.get("role") == "user":
            builder.user(message)
    events = builder.chain.events
    if events and builder.dropped:
        first = dict(events[0].attributes or {})
        first["environment_details_dropped"] = builder.dropped
        events[0] = replace(events[0], attributes=first)
    return events


def roo_events(source: Any) -> list[TraceEvent]:
    return cline_events(source, "roo-task")


def cline_task_events(source: Any) -> list[TraceEvent]:
    return cline_events(source, "cline-task")


__all__ = ["cline_events", "cline_task_events", "roo_events", "usage_of"]
