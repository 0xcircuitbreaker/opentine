"""``tine enable`` for agent CLIs whose hook files are not Claude-shaped.

Each gets the same ``tine hook capture --agent NAME --repo PATH`` shim
(:mod:`opentine._enable_shims`), on the events its documentation names:

* **GitHub Copilot CLI**: its own file ``$COPILOT_HOME/hooks/opentine.json``
  (default ``~/.copilot/hooks``), ``{"version": 1, "hooks": {Event: [{"type":
  "command", "bash", "powershell", "timeoutSec"}]}}``. PascalCase event names
  make Copilot send the snake_case, Claude-shaped payload
  (docs.github.com/en/copilot/reference/hooks-configuration).
* **Factory Droid**: ``~/.factory/hooks.json``, event names as top-level keys
  holding Claude-style matcher groups, timeout in seconds
  (docs.factory.com/reference/hooks-reference).
* **Google Antigravity**: ``~/.gemini/config/hooks.json``, an object keyed by
  hook name; opentine owns the ``opentine-capture`` key. Its payload does not
  name the event, so every command passes ``--event``
  (antigravity.google/docs/hooks).

Only entries whose command carries :data:`SHIM_MARKER` are added or removed.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any

from opentine._cli_hook_agents import _tine
from opentine._enable_shims import SHIM_MARKER

TIMEOUT = 30
OWN_KEY = "opentine-capture"
EVENTS = {
    "copilot": ("UserPromptSubmit", "PostToolUse", "Stop", "SessionEnd"),
    "droid": ("UserPromptSubmit", "PostToolUse", "Stop", "SessionEnd"),
    "antigravity": ("PreInvocation", "PostToolUse", "Stop"),
}
NATIVE = tuple(sorted(EVENTS))


def config_path(name: str) -> Path:
    if name == "copilot":
        value = os.environ.get("COPILOT_HOME")
        base = Path(value).expanduser() if value else Path.home() / ".copilot"
        return base / "hooks" / "opentine.json"
    if name == "droid":
        return Path.home() / ".factory" / "hooks.json"
    return Path.home() / ".gemini" / "config" / "hooks.json"


def command(name: str, repo: Path, event: str | None = None) -> str:
    argv = [*_tine(), *SHIM_MARKER.split(), name, "--repo", str(repo)]
    if event:
        argv += ["--event", event]
    if os.name == "nt":
        return " ".join(f'"{part}"' if " " in part else part for part in argv)
    return shlex.join(argv)


def _ours(entry: Any) -> bool:
    return SHIM_MARKER in json.dumps(entry) if isinstance(entry, dict) else False


def _strip(events: dict[str, Any]) -> dict[str, Any]:
    """*events* (``{Event: [entry or group]}``) without opentine's entries."""
    out: dict[str, Any] = {}
    for event, items in events.items():
        if not isinstance(items, list):
            out[event] = items
            continue
        kept = []
        for item in items:
            inner = item.get("hooks") if isinstance(item, dict) else None
            if isinstance(inner, list):
                rest = [entry for entry in inner if not _ours(entry)]
                if rest or not inner:
                    kept.append({**item, "hooks": rest})
            elif not _ours(item):
                kept.append(item)
        if kept or not items:
            out[event] = kept
    return out


def without_shims(document: dict[str, Any], name: str) -> dict[str, Any]:
    updated = json.loads(json.dumps(document))
    if name == "antigravity":
        if _ours(updated.get(OWN_KEY)):
            del updated[OWN_KEY]
        return updated
    if name == "copilot":
        hooks = updated.get("hooks")
        if isinstance(hooks, dict):
            updated["hooks"] = _strip(hooks)
            if not updated["hooks"] and document.get("hooks"):
                return {}  # the file was ours alone
        return updated
    return _strip(updated)


def with_shims(document: dict[str, Any], name: str, repo: Path) -> dict[str, Any]:
    updated = without_shims(document, name)
    if name == "antigravity":
        entry = {"type": "command", "timeout": TIMEOUT}
        hook: dict[str, Any] = {"enabled": True}
        for event in EVENTS[name]:
            handler = {**entry, "command": command(name, repo, event)}
            hook[event] = [{"matcher": ".*", "hooks": [handler]}] if event == "PostToolUse" \
                else [handler]  # fmt: skip
        updated[OWN_KEY] = hook
        return updated
    events = updated.setdefault("hooks", {}) if name == "copilot" else updated
    if not isinstance(events, dict):
        raise ValueError("its 'hooks' setting is not an object; not touching it")
    if name == "copilot":
        updated.setdefault("version", 1)
    for event in EVENTS[name]:
        items = events.setdefault(event, [])
        if not isinstance(items, list):
            raise ValueError(f"its {event} setting is not a list; not touching it")
        text = command(name, repo)
        if name == "copilot":
            items.append({"type": "command", "bash": text, "powershell": text,
                          "timeoutSec": TIMEOUT})  # fmt: skip
        else:
            group: dict[str, Any] = {"hooks": [{"type": "command", "command": text,
                                                "timeout": TIMEOUT}]}  # fmt: skip
            if event == "PostToolUse":
                group["matcher"] = "*"
            items.append(group)
    return updated


__all__ = ["EVENTS", "NATIVE", "OWN_KEY", "command", "config_path", "with_shims",
           "without_shims"]  # fmt: skip
