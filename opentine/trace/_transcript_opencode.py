"""Import an OpenCode session (and its subagent sessions) from OpenCode's SQLite store.

Source shapes follow OpenCode's own code (github.com/anomalyco/opencode, branch
``dev``): an assistant ``message.data`` carries ``modelID``, ``providerID``,
``cost`` and ``tokens{input, output, reasoning, cache{read, write}}``, and
``packages/core/src/session/usage.ts`` fills those as *exclusive* buckets
(``input`` is non-cached input, ``output`` excludes reasoning). A ``part.data``
of ``type: "tool"`` holds ``tool``, ``callID`` and ``state{input, output}``;
``text`` and ``reasoning`` parts hold the message's prose. A child session
(``session.parent_id``) is a subagent run by the ``task`` tool: it becomes a
typed ``subagent`` event under the parent session's last tool call before it,
and its own events hang under that edge.

The source may be ``opencode.db`` (newest top-level session) or
``opencode.db::<session id>``. ``cost`` is the file's claim, kept as
``opencode.cost``; the import is priced from the catalog.
"""

from __future__ import annotations

import json
from typing import Any

from opentine.trace import _opencode_db as db
from opentine.trace._provider_alias import canonical_provider
from opentine.trace._transcript_common import (
    MAX_EVENTS,
    Chain,
    bounded_id,
    label,
    session_trace_id,
    text_of,
)
from opentine.trace._transcript_usage import count
from opentine.trace.schema import TraceEvent

OPENCODE_FORMAT = "opencode-session"
MAX_DEPTH = 8


def _json(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, (str, bytes)):
        return {}
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def _usage(tokens: Any) -> dict[str, int]:
    if not isinstance(tokens, dict):
        return {}
    cache = tokens.get("cache") if isinstance(tokens.get("cache"), dict) else {}
    usage = {
        "input": count(tokens.get("input")),
        "output": count(tokens.get("output")),
        "reasoning": count(tokens.get("reasoning")),
        "cache_read": count(cache.get("read")),
        "cache_write_5m": count(cache.get("write")),
    }
    return {key: value for key, value in usage.items() if value}


class _Reader:
    def __init__(self, connection: Any, root: str) -> None:
        self.connection = connection
        self.trace_id = session_trace_id(root)
        self.events: list[TraceEvent] = []
        self.rows = 0
        self.skipped = 0
        self.sessions = 0
        self.spawned: dict[str, str] = {}  # child session id -> its task tool span

    def _rows(self, sql: str, session: str) -> list[tuple[Any, ...]]:
        rows = self.connection.execute(sql, (session, db.MAX_ROWS - self.rows + 1)).fetchall()
        self.rows += len(rows)
        if self.rows > db.MAX_ROWS:
            raise ValueError("OpenCode session exceeds the import row limit")
        return rows

    def session(self, session: str, prefix: str, parent: str | None, depth: int) -> None:
        self.sessions += 1
        if depth > MAX_DEPTH or self.sessions > db.MAX_SESSIONS:
            self.skipped += 1
            return
        messages = self._rows(
            "SELECT id, time_created, data FROM message WHERE session_id = ? "
            "ORDER BY time_created, id LIMIT ?",
            session,
        )
        parts: dict[str, list[dict[str, Any]]] = {}
        for message_id, data in self._rows(
            "SELECT message_id, data FROM part WHERE session_id = ? "
            "ORDER BY time_created, id LIMIT ?",
            session,
        ):
            parts.setdefault(str(message_id), []).append(_json(data))
        chain = Chain(self.trace_id, prefix=prefix, parent=parent)
        children = db.child_sessions(self.connection, session)
        for message_id, created, raw in messages:
            data = _json(raw)
            self._message(chain, str(message_id), (created or 0) / 1000, data, parts)
            if len(self.events) + len(chain.events) > MAX_EVENTS:
                raise ValueError("trace import exceeds maximum event count")
        self.events.extend(chain.events)
        tools = [item for item in chain.events if item.kind == "tool"]
        for child in children:
            key = bounded_id(child, "session")
            fallback = tools[-1].span_id if tools else parent
            spawner = self.spawned.get(child, fallback)
            edge = f"{prefix}sub-{key}"
            when = chain.events[-1].timestamp if chain.events else 0.0
            link = Chain(self.trace_id, prefix="", parent=spawner)
            source = {"source": OPENCODE_FORMAT}
            link.add("subagent", when, edge, actor="subagent", inputs={"session_id": key},
                     attributes=source)  # fmt: skip
            self.events.extend(link.events)
            self.session(child, f"{edge}/", link.events[-1].span_id, depth + 1)

    def _message(self, chain: Chain, mid: str, when: float, data: dict, parts: dict) -> None:
        role = data.get("role")
        mine = parts.get(mid, [])
        text = "\n".join(text_of(p.get("text")) for p in mine if p.get("type") == "text")
        span = f"msg-{bounded_id(mid, 'message')}"
        if role == "user":
            chain.add("human", when, span, actor="user", inputs={"role": "user", "text": text},
                      attributes={"source": OPENCODE_FORMAT})  # fmt: skip
            return
        if role != "assistant":
            self.skipped += 1
            return
        attributes: dict[str, Any] = {"source": OPENCODE_FORMAT}
        cost = data.get("cost")
        if isinstance(cost, (int, float)) and not isinstance(cost, bool):
            attributes["opencode.cost"] = cost
        outputs: dict[str, Any] = {"text": text}
        reasoning = [text_of(p.get("text")) for p in mine if p.get("type") == "reasoning"]
        if any(reasoning):
            outputs["reasoning"] = "\n".join(reasoning)
        chain.add("model", when, span, actor=label(data.get("agent") or data.get("mode")),
                  model=str(data.get("modelID") or "")[:256],
                  provider=canonical_provider(str(data.get("providerID") or "")[:64]),
                  outputs=outputs, usage=_usage(data.get("tokens")),
                  attributes=attributes)  # fmt: skip
        for part in mine:
            if part.get("type") != "tool":
                continue
            state = part.get("state") if isinstance(part.get("state"), dict) else {}
            call = bounded_id(part.get("callID"), "call")
            name = label(part.get("tool"))
            chain.add("tool", when, f"{span}/call-{call}", actor=name,
                      inputs={"name": name, "arguments": state.get("input"), "tool_call_id": call},
                      outputs={"result": text_of(state.get("output")),
                               "status": str(state.get("status") or "")[:32]},
                      attributes={"source": OPENCODE_FORMAT})  # fmt: skip
            meta = state.get("metadata") if isinstance(state.get("metadata"), dict) else {}
            if isinstance(meta.get("sessionId"), str):  # the task tool names its child
                self.spawned[meta["sessionId"]] = chain.events[-1].span_id


def opencode_events(source: str) -> list[TraceEvent]:
    """Events for one OpenCode session: ``db`` (newest) or ``db::<session id>``."""
    path, session = db.split_source(str(source))
    connection, immutable = db.connect(path)
    try:
        if session is None:
            newest = db.root_sessions(connection, 1)
            if not newest:
                raise ValueError("the OpenCode database holds no sessions")
            session = newest[0][0]
        elif not db.session_exists(connection, session):
            raise ValueError(f"no OpenCode session {session!r} in {path}")
        reader = _Reader(connection, session)
        reader.session(session, "", None, 0)
    finally:
        connection.close()
    events = reader.events
    if events:
        notes = []
        if reader.skipped:
            notes.append(f"skipped {reader.skipped} OpenCode message(s)/session(s)")
        if immutable:
            notes.append("database opened immutable: writes still in its WAL were not read")
        if notes:
            from dataclasses import replace

            from opentine.trace._import_helpers import note_import_warning

            attributes = dict(events[0].attributes or {})
            for note in notes:
                note_import_warning(attributes, note)
            events[0] = replace(events[0], attributes=attributes)
    return events


__all__ = ["OPENCODE_FORMAT", "opencode_events"]
