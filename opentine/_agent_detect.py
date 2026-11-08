"""Which agent CLIs are present on this machine, for ``tine doctor``.

An agent counts as present when its binary is on ``PATH`` or its documented
user directory exists. Each row says how opentine captures it: per-turn hooks
(``tine enable``), a session importer (``tine import --from-default-location``),
or both. Nothing is read beyond ``is_dir``/``which``.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def _home(variable: str, default: str) -> Path:
    value = os.environ.get(variable)
    return Path(value).expanduser() if value else Path.home() / default


def agents() -> list[tuple[str, str, Path, str]]:
    """``(name, binary, user directory, capture)`` for every supported agent CLI."""
    gemini = os.environ.get("GEMINI_CLI_HOME")
    return [
        ("claude-code", "claude", _home("CLAUDE_CONFIG_DIR", ".claude"), "hooks+import"),
        ("codex", "codex", _home("CODEX_HOME", ".codex"), "hooks+import"),
        ("gemini", "gemini", (Path(gemini).expanduser() if gemini else Path.home()) / ".gemini",
         "hooks+import"),
        ("copilot", "copilot", _home("COPILOT_HOME", ".copilot"), "hooks"),
        ("droid", "droid", Path.home() / ".factory", "hooks"),
        ("antigravity", "agy", Path.home() / ".gemini" / "antigravity-cli", "hooks"),
        ("pi", "pi", _home("PI_CODING_AGENT_DIR", os.path.join(".pi", "agent")), "import"),
    ]  # fmt: skip


def present() -> list[str]:
    """``name (capture)`` for each agent CLI found here."""
    found = []
    for name, binary, folder, capture in agents():
        if shutil.which(binary) or folder.is_dir():
            found.append(f"{name} ({capture})")
    return found


__all__ = ["agents", "present"]
