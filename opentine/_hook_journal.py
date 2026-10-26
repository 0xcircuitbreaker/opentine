"""``tine hook event``: an append-only journal of Claude Code subagent hook events.

Claude Code runs a command hook with the event's JSON on **stdin**
(code.claude.com/docs/en/hooks): ``SubagentStart`` carries ``session_id``,
``agent_id`` and ``agent_type``; ``SubagentStop`` adds ``agent_transcript_path``
and ``last_assistant_message``. Only stdin is read -- nothing from the payload
ever reaches an argv, a path or a shell -- and only the ids are kept: a clamped
event name, session id, agent id and agent type, plus the time. The journal
lives at ``<repo>/journal/subagents.jsonl`` and stops growing at
:data:`MAX_JOURNAL_BYTES`. A hook must never break the agent, so every failure
exits 0 quietly.

``tine import --fleet`` reads it back for agent types the transcript lacks; a
``SubagentStop`` without its ``SubagentStart`` (a known Claude Code ordering
gap) is as good as a start, since each record names its agent on its own.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import IO, Any

MAX_PAYLOAD_BYTES = 256 * 1024
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_FIELD = 128
EVENTS = ("SubagentStart", "SubagentStop")
_UNSAFE = re.compile(r"[^A-Za-z0-9._:@-]")
JOURNAL = ("journal", "subagents.jsonl")


def clamp(value: Any) -> str:
    """An id from a payload: printable id characters only, bounded; else ``""``."""
    if not isinstance(value, str):
        return ""
    return _UNSAFE.sub("_", value.strip())[:MAX_FIELD]


def parse_payload(raw: bytes) -> dict[str, str] | None:
    """The journal record for one hook payload, or ``None`` when it is not one."""
    if len(raw) > MAX_PAYLOAD_BYTES:
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(payload, dict) or payload.get("hook_event_name") not in EVENTS:
        return None
    record = {
        "event": payload["hook_event_name"],
        "session_id": clamp(payload.get("session_id")),
        "agent_id": clamp(payload.get("agent_id")),
        "agent_type": clamp(payload.get("agent_type")),
    }
    return record if record["agent_id"] else None


def journal_path(repo_path: Path) -> Path:
    from opentine.repository._paths import internal_path

    folder = internal_path(Path(repo_path), JOURNAL[0])
    folder.mkdir(exist_ok=True)
    return internal_path(Path(repo_path), *JOURNAL)


def append(repo_path: Path, record: dict[str, str]) -> bool:
    path = journal_path(repo_path)
    if path.is_symlink():
        return False
    line = json.dumps({**record, "time": round(time.time(), 3)}, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if os.fstat(fd).st_size + len(line) > MAX_JOURNAL_BYTES:
            return False
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)
    return True


def agent_types(repo_path: Path) -> dict[str, str]:
    """``{agent_id: agent_type}`` from the journal; Start or Stop alone suffices."""
    try:
        path = journal_path(repo_path)
        if path.is_symlink() or not path.is_file():
            return {}
        with open(path, "rb") as handle:
            raw = handle.read(MAX_JOURNAL_BYTES)
    except (OSError, ValueError):
        return {}
    found: dict[str, str] = {}
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(item, dict):
            agent, kind = clamp(item.get("agent_id")), clamp(item.get("agent_type"))
            if agent and kind:
                found[agent] = kind
    return found


def run_event(repo: str | None, stream: IO[bytes] | None = None) -> int:
    """Read one payload from stdin and journal it; always 0 (never block the agent)."""
    try:
        source = stream or sys.stdin.buffer
        record = parse_payload(source.read(MAX_PAYLOAD_BYTES + 1))
        if record is not None and repo:
            from opentine.repo import Repo

            append(Path(Repo.open(Path(repo)).path), record)
    except Exception:  # noqa: BLE001 - a hook must never fail the session
        pass
    return 0


__all__ = ["EVENTS", "MAX_JOURNAL_BYTES", "agent_types", "append", "clamp", "parse_payload",
           "run_event"]  # fmt: skip
