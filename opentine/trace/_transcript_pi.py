"""Import a Pi (pi-coding-agent) session file (``--format pi-session``).

Pi stores every session as JSONL under
``~/.pi/agent/sessions/--<cwd>--/<timestamp>_<session-id>.jsonl``
(``packages/coding-agent/docs/session-format.md``): a ``{"type": "session",
"version", "id", "timestamp", "cwd"}`` header, then entries with ``type``,
``id``, ``parentId`` and ``timestamp``. A ``message`` entry holds one agent
message: ``user`` (``content``), ``assistant`` (``content`` blocks --
``text``, ``thinking``, ``toolCall`` -- plus ``provider``, ``model`` and
``usage`` in exclusive buckets ``input``/``output``/``cacheRead``/
``cacheWrite``, with Pi's own ``cost.total``) or ``toolResult``
(``toolCallId``, ``toolName``, ``content``, ``isError``). Other entry types
(model and thinking-level changes, compaction, labels, extension data) carry
no session content and are skipped.

Entries form a tree (``parentId``) when the user branched; they are imported
in file order, which is the order Pi wrote them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine.trace._transcript_common import (
    SHAPE_ERRORS,
    Chain,
    count,
    label,
    note_skipped,
    records,
    text_of,
)
from opentine.trace.schema import TraceEvent

PI_FORMAT = "pi-session"


def looks_like_pi(record: dict[str, Any]) -> bool:
    return (
        record.get("type") == "session"
        and "version" in record
        and isinstance(record.get("cwd"), str)
        and "id" in record
    )


def _map(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _usage(raw: dict[str, Any]) -> dict[str, int]:
    output = count(raw.get("output")) or 0
    reasoning = count(raw.get("reasoning")) or 0
    reasoning = reasoning if reasoning <= output else 0
    dimensions = {
        "input": count(raw.get("input")),
        "output": output - reasoning,
        "cache_read": count(raw.get("cacheRead")),
        "cache_write_5m": count(raw.get("cacheWrite")),
        "cache_write_1h": count(raw.get("cacheWrite1h")),
        "reasoning": reasoning,
    }
    return {name: value for name, value in dimensions.items() if value}


def _assistant(chain: Chain, entry: dict[str, Any], message: dict[str, Any]) -> None:
    blocks = [b for b in message.get("content") or [] if isinstance(b, dict)]
    texts = [
        b["text"] for b in blocks if b.get("type") == "text" and isinstance(b.get("text"), str)
    ]
    thoughts = [b["thinking"] for b in blocks
                if b.get("type") == "thinking" and isinstance(b.get("thinking"), str)]  # fmt: skip
    calls = [{"id": b.get("id"), "name": b.get("name"), "arguments": b.get("arguments")}
             for b in blocks if b.get("type") == "toolCall"]  # fmt: skip
    outputs: dict[str, Any] = {"text": "".join(texts)}
    if thoughts:
        outputs["reasoning"] = "".join(thoughts)
    if calls:
        outputs["tool_calls"] = calls
    attributes: dict[str, Any] = {"source": PI_FORMAT}
    cost = _map(_map(message.get("usage")).get("cost")).get("total")
    if isinstance(cost, (int, float)) and not isinstance(cost, bool):
        attributes["pi.cost_usd"] = cost
    if isinstance(message.get("stopReason"), str):
        attributes["pi.stop_reason"] = message["stopReason"][:64]
    chain.add("model", entry.get("timestamp"), str(entry.get("id") or ""), actor="pi",
              model=label(message.get("model")), provider=label(message.get("provider")),
              outputs=outputs, usage=_usage(_map(message.get("usage"))),
              attributes=attributes)  # fmt: skip


def _entry(chain: Chain, entry: dict[str, Any]) -> None:
    if entry.get("type") != "message":
        return
    message = _map(entry.get("message"))
    role, when, span = message.get("role"), entry.get("timestamp"), str(entry.get("id") or "")
    attributes = {"source": PI_FORMAT}
    if role == "user":
        chain.add("human", when, span, actor="user",
                  inputs={"text": text_of(message.get("content"))},
                  attributes=attributes)  # fmt: skip
    elif role == "assistant":
        _assistant(chain, entry, message)
    elif role == "toolResult":
        name = label(message.get("toolName") or "tool")
        chain.add("tool", when, span, actor=name,
                  inputs={"name": name, "call_id": message.get("toolCallId")},
                  outputs={"result": text_of(message.get("content")),
                           "is_error": bool(message.get("isError"))},
                  attributes=attributes)  # fmt: skip


def pi_session_events(source: str | Path | list[Any]) -> list[TraceEvent]:
    """Events for one Pi session file, in the order Pi wrote them."""
    chain: Chain | None = None
    skipped = 0
    for record in records(source):
        if chain is None:
            if looks_like_pi(record):
                chain = Chain(f"pi:{record.get('id')}")
            continue
        try:
            _entry(chain, record)
        except SHAPE_ERRORS:
            skipped += 1
    if chain is None:
        raise ValueError("not a Pi session file: no session header")
    return note_skipped(chain.events, skipped)


__all__ = ["PI_FORMAT", "looks_like_pi", "pi_session_events"]
