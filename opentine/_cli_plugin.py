"""``tine plugin export DIR --repo PATH``: build the opentine Claude Code plugin.

Writes the bundle (:mod:`opentine._plugin_bundle`) into a directory you name --
never into ``~/.claude`` or ``$CLAUDE_CONFIG_DIR`` -- for ``claude --plugin-dir
DIR`` or a marketplace. When the old-style ``tine hook install`` SessionEnd hook
is also present, it says so: both would import every session twice.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path

from opentine._cli_common import BRAND, _terminal, console


def add_plugin_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("plugin", help="Export the opentine Claude Code plugin")
    parser.add_argument("action", choices=("export",))
    parser.add_argument("target", metavar="DIR", help="Directory to write the plugin into")
    parser.add_argument("--repo", required=True, help="v3 repository the hooks record into")
    parser.add_argument(
        "--force", action="store_true", help="Overwrite the bundle's files in a non-empty DIR"
    )


def _old_hook_installed() -> bool:
    from opentine._cli_hook_agents import AGENTS, read_config, without_ours

    try:
        return without_ours(read_config(AGENTS["claude-code"].config()))[1] > 0
    except (OSError, ValueError):
        return False


def cmd_plugin(args: argparse.Namespace) -> None:
    from opentine._cli_hook import _repo
    from opentine._plugin_bundle import write

    repo = _repo(args.repo)
    try:
        written = write(Path(args.target), repo, force=args.force)
    except (OSError, ValueError) as exc:
        console.print(f"[red]plugin export refused:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    console.print(f"[{BRAND}]# Wrote[/] {len(written)} file(s) to {_terminal(args.target)}")
    console.print(f"Try it: claude --plugin-dir {_terminal(Path(args.target).resolve())}")
    if _old_hook_installed():
        console.print(
            "[yellow]`tine hook install` already added a SessionEnd import to your Claude Code "
            "settings; run `tine hook uninstall --global --agent claude-code` so each session "
            "is imported once.[/]"
        )


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"plugin": cmd_plugin}

__all__ = ["COMMANDS", "add_plugin_parser", "cmd_plugin"]
