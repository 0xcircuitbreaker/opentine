"""The per-turn shims ``tine enable`` writes into each agent CLI's hook file.

Every shim is the same command -- ``tine hook capture --agent NAME --repo PATH``
(:mod:`opentine._hook_protocol`) -- on the events that CLI documents:

* Claude Code ``settings.json``: ``UserPromptSubmit``, ``PostToolUse``, ``Stop``,
  ``SessionEnd`` (timeout in seconds);
* Codex ``hooks.json``: ``UserPromptSubmit``, ``PostToolUse``, ``Stop`` (seconds);
* Gemini CLI ``settings.json``: ``BeforeAgent``, ``AfterTool``, ``AfterAgent``,
  ``SessionEnd`` (milliseconds; stdout is JSON, which the protocol prints).

Only entries whose command carries :data:`SHIM_MARKER` are added or removed;
``tine hook install``'s session-end import and the user's own hooks are left
alone.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any

from opentine._cli_hook_agents import Agent, _tine

SHIM_MARKER = "hook capture --agent"
EVENTS = {
    "claude-code": ("UserPromptSubmit", "PostToolUse", "Stop", "SessionEnd"),
    "codex": ("UserPromptSubmit", "PostToolUse", "Stop"),
    "gemini": ("BeforeAgent", "AfterTool", "AfterAgent", "SessionEnd"),
}
TOOL_EVENTS = ("PostToolUse", "AfterTool")


def shim_command(agent: Agent, repo: Path) -> str:
    argv = [*_tine(), *SHIM_MARKER.split(), agent.name, "--repo", str(repo)]
    if os.name == "nt":
        return " ".join(f'"{part}"' if " " in part else part for part in argv)
    return shlex.join(argv)


def _is_shim(entry: Any) -> bool:
    return isinstance(entry, dict) and SHIM_MARKER in str(entry.get("command", ""))


def without_shims(document: dict[str, Any]) -> dict[str, Any]:
    """A copy of *document* with every opentine shim (and groups left empty) gone."""
    updated = json.loads(json.dumps(document))
    hooks = updated.get("hooks")
    if not isinstance(hooks, dict):
        return updated
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        kept, removed = [], 0
        for group in groups:
            inner = group.get("hooks") if isinstance(group, dict) else None
            if isinstance(inner, list) and any(_is_shim(item) for item in inner):
                removed += 1
                rest = [item for item in inner if not _is_shim(item)]
                if not rest:
                    continue
                group["hooks"] = rest
            kept.append(group)
        hooks[event] = kept
        if removed and not kept:
            del hooks[event]
    if not hooks and isinstance(document.get("hooks"), dict) and document["hooks"]:
        del updated["hooks"]
    return updated


def with_shims(document: dict[str, Any], agent: Agent, repo: Path) -> dict[str, Any]:
    updated = without_shims(document)
    hooks = updated.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("its 'hooks' setting is not an object; not touching it")
    seconds = 30
    for event in EVENTS[agent.name]:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError(f"its hooks.{event} setting is not a list; not touching it")
        timeout = seconds * 1000 if agent.name == "gemini" else seconds
        entry: dict[str, Any] = {
            "type": "command",
            "command": shim_command(agent, repo),
            "timeout": timeout,
        }
        group: dict[str, Any] = {"hooks": [entry]}
        if agent.name == "gemini":
            entry["name"] = "opentine-capture"
        if event in TOOL_EVENTS or agent.name == "gemini":
            group["matcher"] = "*"
        groups.append(group)
    return updated


def render(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


__all__ = ["EVENTS", "SHIM_MARKER", "render", "shim_command", "with_shims", "without_shims"]
