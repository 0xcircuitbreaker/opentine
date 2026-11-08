"""``tine import --format agent-trace``: Agent Trace records as a run (0.45).

The reverse of ``tine export --format agent-trace`` (:mod:`opentine._agent_trace`).
An Agent Trace record (https://agent-trace.dev/, schema ``v1/trace-record``)
says which contributor wrote which line ranges of which files; it carries no
prompts, outputs or diffs. The import keeps exactly that and fabricates nothing:

* one ``model`` event per conversation (its ``contributor.model_id`` and
  ``url``), the parent of
* one ``tool`` event per file the conversation touched, actor
  ``agent_trace.attribution``, whose arguments are the path, the ranges (with
  any ``content_hash``) and the contributor type.

The attribution event is *not* a write tool, so ``tine blame`` never reports an
imported record as having written content it did not record. ``vcs`` (the
revision the ranges refer to) rides on every event's attributes. A file holding
one record, a JSON array of records, or JSONL is accepted.
"""

from __future__ import annotations

import json
from typing import Any

from opentine.redaction import redact_value
from opentine.trace._import_guard import shape_checked
from opentine.trace._transcript_common import bounded_id, event
from opentine.trace.schema import TraceEvent

TOOL = "agent_trace.attribution"
MAX_RECORDS = 10_000
MAX_EVENTS = 100_000


def _records(text: str) -> list[dict[str, Any]]:
    try:
        decoded: Any = json.loads(text)
    except ValueError:
        decoded = [json.loads(line) for line in text.splitlines() if line.strip()]
    items = decoded if isinstance(decoded, list) else [decoded]
    records = [item for item in items[:MAX_RECORDS] if isinstance(item, dict)]
    if not records or not all(isinstance(item.get("files"), list) for item in records):
        raise ValueError("not an Agent Trace record: no 'files' array")
    return records


def _vcs(record: dict[str, Any]) -> dict[str, str]:
    vcs = record.get("vcs") if isinstance(record.get("vcs"), dict) else {}
    return {
        f"agent_trace.vcs.{k}": str(v)[:256] for k, v in vcs.items() if k in ("type", "revision")
    }


def _ranges(value: Any) -> list[dict[str, Any]]:
    out = []
    for item in value if isinstance(value, list) else []:
        if isinstance(item, dict) and isinstance(item.get("start_line"), int):
            keep = ("start_line", "end_line", "content_hash")
            out.append({key: item[key] for key in keep if key in item})
    return out


def agent_trace_events(data: bytes | str) -> list[TraceEvent]:
    """Events for every conversation and file in the Agent Trace record(s)."""
    raw = data.encode() if isinstance(data, str) else data
    try:
        records = _records(shape_checked(raw).decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"not an Agent Trace record: {exc}") from exc
    trace = bounded_id(str(records[0].get("id") or "") or str(len(records)), "agent-trace")
    events: list[TraceEvent] = []
    by_conversation: dict[tuple[str, str], str] = {}
    for number, record in enumerate(records):
        when, extra = record.get("timestamp"), _vcs(record)
        tool = record.get("tool") if isinstance(record.get("tool"), dict) else {}
        extra["agent_trace.tool"] = f"{tool.get('name', '')} {tool.get('version', '')}".strip()
        for entry in record["files"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                continue
            for conversation in entry.get("conversations") or []:
                if not isinstance(conversation, dict) or len(events) >= MAX_EVENTS:
                    continue
                who = conversation.get("contributor")
                who = who if isinstance(who, dict) else {}
                model, url = str(who.get("model_id") or ""), str(conversation.get("url") or "")
                key = (model, url)
                if key not in by_conversation:
                    span = f"conversation-{number}-{len(by_conversation)}"
                    by_conversation[key] = span
                    provider, _, name = model.rpartition("/")
                    events.append(event(
                        "model", when, trace, span, model=name or model, provider=provider,
                        inputs={}, attributes={**extra, "agent_trace.url": url[:2048]},
                    ))  # fmt: skip
                events.append(event(
                    "tool", when, trace, f"file-{len(events)}", parent=by_conversation[key],
                    actor=TOOL, attributes=extra,
                    inputs={"arguments": redact_value({
                        "path": entry["path"][:4096],
                        "contributor": str(who.get("type") or "unknown")[:32],
                        "ranges": _ranges(conversation.get("ranges")),
                    })},
                ))  # fmt: skip
    if not events:
        raise ValueError("Agent Trace record attributes no file")
    return events


__all__ = ["TOOL", "agent_trace_events"]
