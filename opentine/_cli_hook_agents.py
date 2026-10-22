"""Where each agent CLI reads its session-end hooks, and editing them safely.

Each CLI documents a JSON hook file with the same three-level shape --
``hooks.<Event>[] = {"matcher"?, "hooks": [{"type": "command", "command": ...}]}``:

* Claude Code: ``~/.claude/settings.json`` (``CLAUDE_CONFIG_DIR``), ``SessionEnd``
  (https://docs.claude.com/en/docs/claude-code/hooks);
* Codex: ``~/.codex/hooks.json`` (``CODEX_HOME``), ``SessionEnd``, timeout in
  seconds and capped at 3, so the import is started in the background
  (https://learn.chatgpt.com/docs/hooks);
* Gemini CLI: ``~/.gemini/settings.json`` (``GEMINI_CLI_HOME``), ``SessionEnd``,
  timeout in milliseconds, stdout reserved for JSON so the import's output is
  discarded (google-gemini/gemini-cli ``docs/hooks/index.md``).

Editing rules: the file must parse as a JSON object or nothing is written; a
symlinked file is refused (an atomic replace would cut the link); the original
is copied to ``<file>.tine-backup`` before the first change; only entries whose
command carries :data:`MARKER` are ever replaced or removed, so every other
hook the user has stays exactly as it was.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Every command opentine installs carries this, and nothing else is ever touched.
MARKER = "import latest --from-default-location"
BACKUP_SUFFIX = ".tine-backup"
MAX_CONFIG_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Agent:
    name: str
    source_format: str
    env: str
    home: str
    file: str
    timeout: int
    background: bool = False  # the CLI kills the hook before an import could finish
    quiet: bool = False  # the CLI parses the hook's stdout

    def config(self) -> Path:
        value = os.environ.get(self.env)
        if self.env == "GEMINI_CLI_HOME":  # it replaces the home directory itself
            return (Path(value).expanduser() if value else Path.home()) / ".gemini" / self.file
        base = Path(value).expanduser() if value else Path.home() / self.home
        return base / self.file


AGENTS = {
    "claude-code": Agent("claude-code", "claude-code-transcript", "CLAUDE_CONFIG_DIR", ".claude",
                         "settings.json", 120),
    "codex": Agent("codex", "codex-session", "CODEX_HOME", ".codex", "hooks.json", 3,
                   background=True),
    "gemini": Agent("gemini", "gemini-session", "GEMINI_CLI_HOME", ".gemini", "settings.json",
                    120_000, quiet=True),
}  # fmt: skip


def _tine() -> list[str]:
    found = shutil.which("tine")
    if found:
        return [str(Path(found).resolve())]
    # -I: agent hooks run in project directories; keep cwd off sys.path.
    return [sys.executable, "-I", "-c", "from opentine.cli import main; main()"]


def command(agent: Agent, repo: Path) -> str:
    """The shell command the hook runs: import the newest session into *repo*."""
    argv = [*_tine(), *MARKER.split(), "--format", agent.source_format, "--repo", str(repo)]
    if os.name == "nt":
        text = " ".join(f'"{part}"' if " " in part else part for part in argv)
        quiet = " >NUL 2>&1"
        return f'start "" /b {text}{quiet}' if agent.background else text + quiet
    text = shlex.join(argv)
    if agent.background:
        return f"({text} >/dev/null 2>&1 &)"
    return f"{text} >/dev/null 2>&1" if agent.quiet else text


def _ours(entry: Any) -> bool:
    return isinstance(entry, dict) and MARKER in str(entry.get("command", ""))


def read_config(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"{path} is a symlink; edit its target by hand or pass a real file")
    if not path.exists():
        return {}
    data = path.read_bytes()
    if len(data) > MAX_CONFIG_BYTES:
        raise ValueError(f"{path} is too large to edit safely")
    try:
        document = json.loads(data) if data.strip() else {}
    except ValueError as exc:
        raise ValueError(f"{path} is not valid JSON; not touching it ({exc})") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a JSON object; not touching it")
    return document


def _groups(document: dict[str, Any]) -> list[Any]:
    hooks = document.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("its 'hooks' setting is not an object; not touching it")
    groups = hooks.setdefault("SessionEnd", [])
    if not isinstance(groups, list):
        raise ValueError("its hooks.SessionEnd setting is not a list; not touching it")
    return groups


def without_ours(document: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """A copy of *document* with opentine's entries gone, and how many there were."""
    updated = json.loads(json.dumps(document))
    groups = _groups(updated)
    removed = 0
    kept = []
    for group in groups:
        inner = group.get("hooks") if isinstance(group, dict) else None
        if isinstance(inner, list):
            mine = [entry for entry in inner if _ours(entry)]
            removed += len(mine)
            if mine and len(mine) == len(inner):
                continue  # a group that held only our hook goes with it
            group["hooks"] = [entry for entry in inner if not _ours(entry)]
        kept.append(group)
    groups[:] = kept
    original = document.get("hooks") if isinstance(document.get("hooks"), dict) else {}
    if not groups and (removed or "SessionEnd" not in original):
        del updated["hooks"]["SessionEnd"]
    if not updated["hooks"] and (removed or "hooks" not in document):
        del updated["hooks"]
    return updated, removed


def with_ours(document: dict[str, Any], agent: Agent, repo: Path) -> dict[str, Any]:
    updated, _ = without_ours(document)
    entry: dict[str, Any] = {"type": "command", "command": command(agent, repo),
                             "timeout": agent.timeout}  # fmt: skip
    if agent.name == "gemini":
        entry["name"] = "opentine-import"
    group: dict[str, Any] = {"hooks": [entry]}
    if agent.name == "gemini":
        group["matcher"] = "*"
    _groups(updated).append(group)
    return updated


def write_config(path: Path, document: dict[str, Any]) -> Path | None:
    """Back up the original once, then replace *path* atomically; the backup's path."""
    backup = None
    if path.exists():
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        if not backup.exists():
            shutil.copy2(path, backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(document, indent=2) + "\n")
        os.chmod(name, mode)
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return backup


__all__ = ["AGENTS", "MARKER", "Agent", "command", "read_config", "with_ours", "without_ours",
           "write_config"]  # fmt: skip
