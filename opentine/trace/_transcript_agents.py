"""Claude Code subagent transcripts: ``<session>/subagents/agent-*.jsonl``.

Current Claude Code no longer writes subagent work into the session file as
``isSidechain`` lines; each subagent gets its own transcript in a ``subagents``
folder beside the session. Importing only the session file dropped every
subagent model call -- most of a session's calls and cost, with no warning
(final security pass 2, #3). Each subagent file is read with the same bounds as
the session, its events keep their own span ids (prefixed with the agent id) and
its first event hangs under the tool step whose result named that agent.

Bounded: at most :data:`MAX_AGENT_FILES` files, real files only (no symlinks),
each file on disk read once (a hard link or second path to the same inode, or to
the session itself, is skipped), the session's byte budget shared across all of
them and charged before a file is parsed -- whether its import then succeeds or
not -- and the transcript event cap across the whole session. Whatever is left
out is counted in a warning on the first event, never silently dropped.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from opentine.trace._import_helpers import note_import_warning
from opentine.trace._transcript_common import (
    MAX_EVENTS,
    MAX_SOURCE_BYTES,
    SHAPE_ERRORS,
    bounded_id,
    event,
    records,
)
from opentine.trace.schema import TraceEvent

MAX_AGENT_FILES = 1_000


def build(source: Any, builder: Any, *, total_limit: int = MAX_SOURCE_BYTES) -> int:
    """Feed every record of *source* to *builder*; how many were skipped."""
    skipped = 0
    for record in records(source, total_limit=total_limit):
        try:
            builder.feed(record)
        except SHAPE_ERRORS:
            skipped += 1
            builder.pending, builder.held = [], []
    try:
        builder.flush()
    except SHAPE_ERRORS:
        skipped += 1
    return skipped


def agent_files(session: Path) -> list[Path]:
    """The subagent transcripts beside *session*, sorted; regular files only."""
    folder = session.with_suffix("") / "subagents"
    if folder.is_symlink() or not folder.is_dir():
        return []
    found = [
        path for path in folder.glob("agent-*.jsonl") if not path.is_symlink() and path.is_file()
    ]
    return sorted(found)


def with_subagents(
    session: Path,
    events: list[TraceEvent],
    links: dict[str, str],
    make_builder: Callable[..., Any],
) -> list[TraceEvent]:
    """*events* followed by every subagent's events, each linked to its spawner."""
    files = agent_files(session)
    trace_id = events[0].trace_id
    budget = MAX_SOURCE_BYTES - _size(session)
    combined = list(events)
    left_out = max(0, len(files) - MAX_AGENT_FILES)
    seen = {_identity(session)}
    duplicates = 0
    for path in files[:MAX_AGENT_FILES]:
        identity = _identity(path)
        if identity is None or identity in seen:
            duplicates += identity is not None
            left_out += identity is None
            continue
        seen.add(identity)
        size = _size(path)
        agent = bounded_id(path.stem.removeprefix("agent-"), "agentId")
        edge = _edge(trace_id, agent, links.get(agent), combined)
        builder = make_builder(trace_id, f"agent-{agent}/", edge.span_id)
        if size > budget:
            left_out += 1
            continue
        budget -= size  # charged up front: a file that then fails still cost a read
        try:
            build(path, builder, total_limit=max(size, 0))
        except (OSError, ValueError):
            left_out += 1
            continue
        found = builder.chain.events if builder.chain else []
        for nested, span in builder.agents.items():  # a subagent's own subagents (0.13)
            links.setdefault(nested, span)
        if len(combined) + len(found) + 1 > MAX_EVENTS:
            left_out += 1
            continue
        if found:  # the typed edge first, then the subagent's own events under it
            combined.append(edge)
            combined.extend(found)
    if duplicates:
        first = combined[0]
        attributes = dict(first.attributes or {})
        note_import_warning(
            attributes, f"{duplicates} duplicate subagent transcript(s) skipped (same file)"
        )
        combined[0] = replace(first, attributes=attributes)
    if left_out:
        first = combined[0]
        attributes = dict(first.attributes or {})
        note_import_warning(attributes, f"{left_out} subagent transcript(s) not imported")
        combined[0] = replace(first, attributes=attributes)
    return combined


def _edge(trace_id: str, agent: str, spawner: str | None, events: list[TraceEvent]) -> TraceEvent:
    """A typed ``subagent`` event: the delegating tool call -> the subagent's steps.

    Without it a subagent's first event hung directly under the tool call, and
    nothing in the run said "a separate agent did this" -- the edge carries the
    agent id, so the delegation survives import, storage and export as a link.
    """
    when = next((item.timestamp for item in events if item.span_id == spawner), 0.0)
    return event(
        "subagent",
        when,
        trace_id,
        f"agent-{agent}/spawn",
        parent=spawner,
        actor=agent,
        inputs={"agent_id": agent},
        attributes={"source": "claude-code-transcript", "claude_code.subagent": True},
    )


def _identity(path: Path) -> tuple[Any, ...] | None:
    """One key per file on disk (device, inode): hard links share it."""
    try:
        stat = path.stat()
        return (stat.st_dev, stat.st_ino)
    except OSError:
        return None


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


__all__ = ["MAX_AGENT_FILES", "agent_files", "build", "with_subagents"]
