"""Argument parsers for ``tine who``, ``actions``, ``touched`` and ``audit``."""

from __future__ import annotations

import argparse
from typing import Any

from opentine._actions_query import GROUP_KEYS

_FILTERS = (
    ("--tool", "Tool name (substring, or a glob with * ? [)"),
    ("--program", "Program a command ran (rm, git, curl ...)"),
    ("--path", "A path the action named (substring or glob)"),
    ("--host", "A host the action contacted (host and its subdomains, or a glob)"),
    ("--mcp", "MCP server, or SERVER/TOOL"),
    ("--verb", "exec, file.read, file.write, file.delete, net, mcp, git, spawn_subagent"),
    ("--agent", "Harness, transcript source or framework that produced the run"),
    ("--model", "Model name (substring)"),
    ("--provider", "Provider name (substring)"),
    ("--session", "Session id (substring)"),
    ("--run", "Run id prefix"),
    ("--since", "Only actions at or after this time (7d, 24h, 30m, YYYY-MM-DD)"),
    ("--until", "Only actions at or before this time"),
)


def _add_scope(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", metavar="PATH", help="Read a v3 repository instead")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON object")


def _add_filters(parser: argparse.ArgumentParser) -> None:
    for flag, text in _FILTERS:
        parser.add_argument(flag, help=text)
    parser.add_argument("--cmd", action="append", default=[], help="Command text (repeatable)")
    parser.add_argument("--errors", action="store_true", help="Only actions that failed")


def add_actions_parsers(sub: Any) -> None:
    who = sub.add_parser("who", help="Which agents did an action: tools, commands, paths, hosts")
    _add_filters(who)
    who.add_argument("--by", default="agent,model", help=f"Group by: {', '.join(GROUP_KEYS)}")
    who.add_argument("--list", action="store_true", help="List matching actions, not groups")
    who.add_argument("--limit", type=int, default=50, help="Rows to show; 0 for all")
    _add_scope(who)
    actions = sub.add_parser("actions", help="One run's actions, in order")
    actions.add_argument("run_id")
    actions.add_argument("--verb", help="Only actions with this verb")
    _add_scope(actions)
    touched = sub.add_parser("touched", help="Which agents wrote or deleted a path")
    touched.add_argument("--path", required=True, help="Path substring or glob")
    touched.add_argument("--by", default="agent,model", help=f"Group by: {', '.join(GROUP_KEYS)}")
    touched.add_argument("--since")
    _add_scope(touched)
    audit = sub.add_parser("audit", help="Check what agents did against a policy file")
    audit.add_argument("--policy", required=True, metavar="FILE", help="TOML or JSON rule file")
    audit.add_argument("--strict", action="store_true", help="Exit 1 on warn rules too")
    audit.add_argument(
        "--allow-partial", action="store_true", help="Pass even if some runs were not fully read"
    )
    _add_scope(audit)


__all__ = ["_FILTERS", "add_actions_parsers"]
