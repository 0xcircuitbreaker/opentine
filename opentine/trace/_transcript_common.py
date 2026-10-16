"""Shared reading and accounting for agent-CLI session transcripts.

Every agent CLI keeps its own log of a session -- Claude Code, Codex, Gemini CLI
and Qwen Code each write one JSON record per line under the user's home
directory. Those logs carry what OpenTine needs to price a run after the fact
(the model, and each API call's token usage), so importing them makes a session
that was never run under ``tine run`` a priced, replayable run all the same.

The three usage conventions the CLIs inherit from their providers differ, and
are spelled out once here so no importer re-derives them:

* **Anthropic** (Claude Code): ``input_tokens`` excludes cache reads and writes,
  which arrive beside it; ``output_tokens`` includes thinking.
* **OpenAI** (Codex): ``input_tokens`` *includes* ``cached_input_tokens`` and
  ``output_tokens`` includes ``reasoning_output_tokens``.
* **Gemini** (Gemini CLI, Qwen Code): ``promptTokenCount`` includes
  ``cachedContentTokenCount``; ``candidatesTokenCount`` excludes thoughts; the
  tool-use prompt is billed as input.

A transcript is written by the agent itself, on a machine the agent could also
write to, so every imported run records that its source was agent-writable.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

from opentine._jsonsafe import json_safe as _safe
from opentine.trace._import_guard import bounded_lines, shape_checked
from opentine.trace._import_helpers import note_import_warning, timestamp
from opentine.trace._transcript_usage import anthropic_usage, count, gemini_usage, inclusive_usage
from opentine.trace.schema import TraceEvent

MAX_LINE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_EVENTS = 100_000
#: A session id kept verbatim: short and id-shaped. Anything else is untrusted
#: text that every event would otherwise carry a full copy of.
_SESSION_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
#: Longest name copied onto an event (the event's own ``actor`` is clipped alike).
MAX_LABEL_CHARS = 256


def capture_marker(source_format: str) -> dict[str, Any]:
    """The run metadata saying how a transcript-imported run was captured."""
    return {
        "method": "transcript-import",
        "source_format": source_format,
        # The agent wrote this file and could have edited it; nothing outside
        # the agent observed these events.
        "agent_writable": True,
    }


def records(
    source: str | Path | Iterable[Any], *, total_limit: int = MAX_SOURCE_BYTES
) -> Iterator[dict[str, Any]]:
    """JSON objects from a path or an iterable of lines, bounded and shape-checked.

    An unparsable, over-dense or non-object line is skipped, as the JSONL importer
    skips one: a transcript being appended to while it is read ends mid-line.
    """
    if isinstance(source, (str, Path)):
        with Path(source).open("rb") as handle:
            yield from _decoded(
                bounded_lines(handle, line_limit=MAX_LINE_BYTES, total_limit=total_limit)
            )
    else:
        yield from _decoded(source)


def _decoded(lines: Iterable[Any]) -> Iterator[dict[str, Any]]:
    for line in lines:
        if isinstance(line, dict):
            yield line
            continue
        if not isinstance(line, (str, bytes)) or not line.strip():
            continue
        try:
            item = json.loads(shape_checked(line))
        except (ValueError, RecursionError, TypeError, UnicodeDecodeError):
            continue
        if isinstance(item, dict):
            yield item


def event(
    kind: str,
    when: Any,
    trace_id: str,
    span_id: str,
    *,
    parent: str | None = None,
    actor: str = "",
    model: str = "",
    provider: str = "",
    inputs: Any = None,
    outputs: Any = None,
    usage: dict[str, int] | None = None,
    duration: float = 0.0,
    attributes: dict[str, Any] | None = None,
) -> TraceEvent:
    """One TraceEvent from transcript fields, every payload JSON-safe."""
    return TraceEvent(
        kind=kind,
        timestamp=timestamp(when),
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent,
        actor=str(actor)[:256],
        model=str(model or "")[:256],
        provider=str(provider or "")[:64],
        duration=max(0.0, float(duration or 0)),
        inputs=_safe(
            inputs if isinstance(inputs, dict) else {} if inputs is None else {"value": inputs}
        ),
        outputs=_safe(
            outputs if isinstance(outputs, dict) else {} if outputs is None else {"value": outputs}
        ),
        usage=dict(usage or {}),
        attributes=_safe(attributes or {}),
    )


def bounded_id(raw: Any, prefix: str = "id") -> str:
    """*raw* when short and id-shaped, else a digest of it.

    Ids a transcript names once can be stamped on many imported events (the
    session id on all of them, a request id on every tool result of a line), so
    an oversized or odd one is replaced by a digest rather than copied N times.
    """
    text = str(raw or "")
    if _SESSION_ID.fullmatch(text):
        return text
    return f"{prefix}-" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def session_trace_id(raw: Any) -> str:
    """A bounded trace id for a transcript's session id (see :func:`bounded_id`)."""
    return bounded_id(raw, "session")


def label(raw: Any) -> str:
    """A name (tool, flag) that may be repeated on several events, clipped."""
    return str(raw or "")[:MAX_LABEL_CHARS]


class Chain:
    """Links each event to the one before it, so a transcript imports as a path."""

    def __init__(self, trace_id: str, *, prefix: str = "", parent: str | None = None) -> None:
        self.trace_id = trace_id
        self.prefix = prefix  # keeps a subagent's span ids apart from its parent's
        self.parent = parent  # the span a subagent's first event hangs under
        self.events: list[TraceEvent] = []
        self._ids: set[str] = set()
        self._next: dict[str, int] = {}

    @property
    def trace_id(self) -> str:
        return self._trace_id

    @trace_id.setter
    def trace_id(self, value: Any) -> None:
        self._trace_id = session_trace_id(value)

    def add(self, kind: str, when: Any, span_id: str, **fields: Any) -> None:
        if len(self.events) >= MAX_EVENTS:
            raise ValueError("trace import exceeds maximum event count")
        base = bounded_id(span_id, "span") if span_id else f"event-{len(self.events)}"
        base = f"{self.prefix}{base}"
        unique = base
        if unique in self._ids:  # a CLI that reuses an id must not fail the import
            suffix = self._next.get(base, 2)
            unique = f"{base}#{suffix}"
            while unique in self._ids:
                suffix += 1
                unique = f"{base}#{suffix}"
            self._next[base] = suffix + 1
        self._ids.add(unique)
        parent = self.events[-1].span_id if self.events else self.parent
        self.events.append(event(kind, when, self.trace_id, unique, parent=parent, **fields))


#: What a well-formed record with an unexpected field type (``"content": 7``)
#: raises in a mapper; such a record is skipped like an unparsable line.
#: ``ValueError`` is not here: the event cap raises it and must stop the import.
SHAPE_ERRORS = (AttributeError, KeyError, TypeError)


def note_skipped(events: list[TraceEvent], skipped: int) -> list[TraceEvent]:
    """Record on the first event how many records were skipped for their shape."""
    if not skipped or not events:
        return events
    attributes = dict(events[0].attributes or {})
    note_import_warning(attributes, f"skipped {skipped} record(s) with unexpected field types")
    return [replace(events[0], attributes=attributes), *events[1:]]


def text_of(content: Any) -> Any:
    """Plain text when *content* is text or all-text blocks, else the structure."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = [
            block.get("text")
            for block in content
            if isinstance(block, dict) and isinstance(block.get("text"), str)
        ]
        if texts and len(texts) == len(content):
            return "".join(texts)
    return content


__all__ = [
    "SHAPE_ERRORS",
    "Chain",
    "anthropic_usage",
    "bounded_id",
    "capture_marker",
    "count",
    "event",
    "gemini_usage",
    "inclusive_usage",
    "label",
    "note_skipped",
    "records",
    "session_trace_id",
    "text_of",
]
