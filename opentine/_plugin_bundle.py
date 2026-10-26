"""The opentine Claude Code plugin, rendered as files (``tine plugin export``).

Layout per code.claude.com/docs/en/plugins-reference: ``.claude-plugin/
plugin.json`` (``name`` is the only required key), ``hooks/hooks.json`` (the
event map wrapped in a top-level ``"hooks"`` key), ``skills/<name>/SKILL.md``
and ``.mcp.json`` at the plugin root.

* Hooks use the **exec form** (``command`` + ``args``): each argument reaches
  the program as is, with no shell to re-parse a path, so nothing needs quoting
  on any platform. They run ``python -I -m opentine.cli`` with the interpreter
  that exported the bundle (``-I`` keeps the project directory off
  ``sys.path``). Claude Code passes each event's JSON on stdin; no payload field
  is ever placed in an argv.
* ``SessionEnd`` imports the newest Claude Code session into the repository;
  ``SubagentStart``/``SubagentStop`` append ids to its journal for
  ``tine import --fleet`` (:mod:`opentine._hook_journal`).
* ``.mcp.json`` starts ``opentine.mcp_server --read-only``: allowlisted read
  tools only (:mod:`opentine._mcp_readonly`).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from opentine._cli_hook_agents import MARKER
from opentine._version import __version__

PLUGIN_NAME = "opentine"
SKILLS = {
    "tine-runs": (
        "List and inspect recorded opentine runs of this project (read-only).",
        "Use the opentine MCP tools `list_runs` and `search_runs` to find runs, then "
        "`show_run` or `inspect_object` to read one. Summarize steps, models and cost.",
    ),
    "tine-diff": (
        "Compare two recorded opentine runs step by step (read-only).",
        "Use the opentine MCP tools `diff_runs` (saved .tine runs) or `semantic_diff` "
        "(repository runs) on the two runs the user named and explain where they diverge.",
    ),
    "tine-actions": (
        "Find which agent ran a program, touched a path or called a host (read-only).",
        "Use the opentine MCP tool `find_actions` with the filters the user asked for and report "
        "the matching actions with their run, agent and time.",
    ),
}


def _python() -> list[str]:
    return [sys.executable, "-I", "-m", "opentine.cli"]


def _hook(args: list[str], timeout: int) -> dict:
    python, *rest = _python()
    return {"type": "command", "command": python, "args": [*rest, *args], "timeout": timeout}


def hooks(repo: Path) -> dict:
    session_end = [*MARKER.split(), "--format", "claude-code-transcript", "--repo", str(repo)]
    event = ["hook", "event", "--repo", str(repo)]
    return {
        "description": "opentine: record finished Claude Code sessions and their subagents",
        "hooks": {
            "SessionEnd": [{"hooks": [_hook(session_end, 60)]}],
            "SubagentStart": [{"hooks": [_hook(event, 10)]}],
            "SubagentStop": [{"hooks": [_hook(event, 10)]}],
        },
    }


def files(repo: Path) -> dict[str, str]:
    """``{relative path: text}`` for the whole plugin."""
    manifest = {
        "name": PLUGIN_NAME,
        "version": __version__,
        "description": "Record Claude Code sessions and subagents as opentine runs; "
        "read-only MCP access to run history.",
        "author": {"name": "opentine"},
        "license": "Apache-2.0",
        "keywords": ["opentine", "tracing", "agents"],
    }
    mcp = {
        "mcpServers": {
            PLUGIN_NAME: {
                "command": sys.executable,
                "args": ["-I", "-m", "opentine.mcp_server", "--read-only"],
            }
        }
    }
    out = {
        ".claude-plugin/plugin.json": manifest,
        "hooks/hooks.json": hooks(repo),
        ".mcp.json": mcp,
    }
    rendered = {path: json.dumps(value, indent=2) + "\n" for path, value in out.items()}
    for name, (description, body) in SKILLS.items():
        rendered[f"skills/{name}/SKILL.md"] = (
            f"---\nname: {name}\ndescription: {description}\n---\n\n{body}\n"
        )
    return rendered


def forbidden_roots() -> list[Path]:
    """Claude Code's own config dirs: the bundle is never written into them."""
    import os

    roots = [Path.home() / ".claude"]
    if value := os.environ.get("CLAUDE_CONFIG_DIR"):
        roots.append(Path(value).expanduser())
    return [root.resolve() for root in roots]


def write(target: Path, repo: Path, *, force: bool = False) -> list[Path]:
    """Write the bundle under *target* (new or empty unless *force*); the paths."""
    if target.is_symlink():
        raise ValueError(f"{target} is a symlink; give a real directory")
    resolved = target.resolve()
    for root in forbidden_roots():
        if resolved == root or root in resolved.parents:
            raise ValueError(
                f"refusing to write inside {root}: export to your own directory and "
                "install it with `claude plugin install` or `--plugin-dir`"
            )
    if resolved.exists() and any(resolved.iterdir()) and not force:
        raise ValueError(f"{target} is not empty (pass --force to overwrite the bundle files)")
    written = []
    for relative, text in files(repo).items():
        path = resolved / relative
        for parent in reversed(path.relative_to(resolved).parents):
            folder = resolved / parent
            if folder.is_symlink():
                raise ValueError(f"{folder} is a symlink; refusing to write through it")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise ValueError(f"{path} is a symlink; refusing to overwrite it")
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return written


__all__ = ["PLUGIN_NAME", "SKILLS", "files", "forbidden_roots", "hooks", "write"]
