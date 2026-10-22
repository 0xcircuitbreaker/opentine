"""Where agent CLIs keep their session logs, for ``tine import --from-default-location``.

A session log is useful only if the user can find it: Claude Code, Codex, Gemini
CLI and Qwen Code each bury theirs under a hashed or dated directory in the home
directory. This module knows those places, lists the newest sessions, and
resolves ``latest`` (or a session-id prefix) to a file, so importing the session
an agent just finished is one command. Only well-known locations are read; the
environment overrides each CLI itself honours (``CLAUDE_CONFIG_DIR``,
``CODEX_HOME``, ``GEMINI_CLI_HOME``, ``QWEN_HOME``, ``XDG_DATA_HOME`` for OpenCode's
SQLite store) are respected.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from opentine.trace._transcript_agents import agent_files

#: How many sessions a listing shows, and how many files one scan may visit.
LIST_LIMIT = 20
MAX_SCANNED = 20_000


@dataclass(frozen=True)
class Session:
    source_format: str
    path: Path
    modified: float
    size: int
    agents: int = 0  # Claude Code subagent transcripts imported with the session


def _home(variable: str, default: str) -> Path:
    value = os.environ.get(variable)
    return Path(value).expanduser() if value else Path.home() / default


def _gemini_root() -> Path:
    value = os.environ.get("GEMINI_CLI_HOME")
    return (Path(value).expanduser() if value else Path.home()) / ".gemini" / "tmp"


def _locations() -> list[tuple[str, Path, str]]:
    """``(format, root, glob)`` for every CLI whose sessions are importable."""
    return [
        ("claude-code-transcript", _home("CLAUDE_CONFIG_DIR", ".claude") / "projects", "*/*.jsonl"),
        ("codex-session", _home("CODEX_HOME", ".codex") / "sessions", "**/rollout-*.jsonl"),
        # GEMINI_CLI_HOME replaces the home directory itself, not ~/.gemini.
        ("gemini-session", _gemini_root(), "*/chats/session-*.json*"),
        ("qwen-session", _home("QWEN_HOME", ".qwen") / "projects", "*/chats/*.jsonl"),
    ]


def sessions(source_format: str | None = None) -> list[Session]:
    """Known session files, newest first, optionally only one format's."""
    found: list[Session] = []
    scanned = 0
    for name, root, pattern in _locations():
        if source_format not in (None, "auto", name) or not root.is_dir():
            continue
        for path in root.glob(pattern):
            scanned += 1
            if scanned > MAX_SCANNED:
                break
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                stat = path.stat()
            except OSError:
                continue
            agents = len(agent_files(path)) if name == "claude-code-transcript" else 0
            found.append(Session(name, path, stat.st_mtime, stat.st_size, agents))
    if source_format in (None, "auto", "opencode-session"):
        found.extend(_opencode_sessions())
    return sorted(found, key=lambda item: item.modified, reverse=True)


def _opencode_sessions() -> list[Session]:
    """OpenCode's top-level sessions, as ``opencode.db::<id>`` sources (read-only)."""
    import sqlite3

    from opentine.trace import _opencode_db as db

    path = db.default_db()
    if not path.is_file() or path.is_symlink():
        return []
    try:
        connection, _ = db.connect(path)
        try:
            rows = db.root_sessions(connection, LIST_LIMIT)
        finally:
            connection.close()
    except (OSError, ValueError, sqlite3.Error):
        return []  # an unreadable or unknown-schema store just lists nothing
    size = path.stat().st_size
    return [Session("opencode-session", Path(f"{path}{db.SEP}{sid}"), ms / 1000, size)
            for sid, ms, _ in rows]  # fmt: skip


def resolve(name: str, source_format: str | None) -> Session:
    """The session *name* means: ``latest``, or a file-name or session-id prefix."""
    candidates = sessions(source_format)
    if not candidates:
        raise ValueError("no agent session logs found in the default locations")
    if name == "latest":
        return candidates[0]
    matches = [item for item in candidates if name in item.path.name]
    if not matches:
        raise ValueError(f"no session log matching {name!r} in the default locations")
    return matches[0]


def print_sessions(source_format: str | None) -> None:
    """List the newest session logs, one per line, for ``--from-default-location``."""
    from datetime import UTC, datetime

    from opentine._cli_common import BRAND, _terminal, console

    found = sessions(source_format)
    if not found:
        console.print("[yellow]No agent session logs found in the default locations.[/]")
        return
    console.print(f"[{BRAND}]# Newest agent sessions[/] ({len(found)} found)")
    for item in found[:LIST_LIMIT]:
        when = datetime.fromtimestamp(item.modified, UTC).strftime("%Y-%m-%d %H:%M")
        extra = f"  (+{item.agents} subagents)" if item.agents else ""
        console.print(
            f"  {when}  {item.source_format:<23} {item.size:>11,}  {_terminal(item.path)}{extra}"
        )
    console.print(
        "Import one with: tine import latest --from-default-location --save run.tine "
        "(or a session id prefix instead of latest)"
    )


__all__ = ["LIST_LIMIT", "Session", "print_sessions", "resolve", "sessions"]
