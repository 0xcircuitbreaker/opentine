"""``tine hook install|uninstall|status``: capture every agent session, zero-config.

``tine hook install --global --repo PATH`` adds one session-end hook to each
agent CLI's own user-level hook file (see :mod:`opentine._cli_hook_agents`), so
every finished Claude Code, Codex or Gemini CLI session is imported into the
repository with ``tine import latest --from-default-location``. ``--agent``
narrows it (repeatable), ``--dry-run`` prints the change instead of making it,
and ``uninstall`` removes only what ``install`` added. Installing twice changes
nothing; a user's other hooks are never edited.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_hook_agents import AGENTS, read_config, with_ours, without_ours, write_config


def add_hook_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "hook", help="Install agent-CLI hooks that import every finished session"
    )
    parser.add_argument("action", choices=("install", "uninstall", "status"))
    parser.add_argument(
        "--global", dest="global_", action="store_true",
        help="Edit the user-level hook files (the only scope supported)",
    )  # fmt: skip
    parser.add_argument(
        "--agent", action="append", choices=sorted(AGENTS),
        help="Only this agent CLI (repeatable; default: every one)",
    )  # fmt: skip
    parser.add_argument("--repo", help="v3 repository the sessions are imported into (install)")
    parser.add_argument("--dry-run", action="store_true", help="Show the change, write nothing")
    return parser


def _fail(message: str) -> SystemExit:
    console.print(f"[red]{message}[/]")
    return SystemExit(1)


def _repo(value: str | None) -> Path:
    if not value:
        raise _fail("tine hook install needs --repo PATH (an existing repository)")
    from opentine.repo import Repo

    path = Path(value).expanduser().resolve()
    try:
        return Path(Repo.open(path).path).resolve()
    except (OSError, ValueError) as exc:
        raise _fail(f"not an opentine repository: {_terminal(path)} ({_terminal(exc)})") from exc


def cmd_hook(args: argparse.Namespace) -> None:
    if not args.global_:
        raise _fail("pass --global: hooks are installed in your user-level agent settings")
    names = args.agent or sorted(AGENTS)
    repo = _repo(args.repo) if args.action == "install" else None
    failed = False
    for name in names:
        agent = AGENTS[name]
        path = agent.config()
        try:
            document = read_config(path)
            if args.action == "status":
                _, count = without_ours(document)
                state = "installed" if count else "not installed"
                console.print(f"  {name:<12} {state:<14} {_terminal(path)}")
                continue
            if args.action == "install":
                assert repo is not None
                updated = with_ours(document, agent, repo)
            else:
                updated, _ = without_ours(document)
            if updated == document:
                console.print(f"  {name:<12} unchanged      {_terminal(path)}")
                continue
            if args.dry_run:
                console.print(f"[{BRAND}]# Would write[/] {_terminal(path)}")
                console.print(json.dumps(updated.get("hooks", {}), indent=2), markup=False)
                continue
            backup = write_config(path, updated)
            done = "installed" if args.action == "install" else "removed"
            note = f" (backup: {_terminal(backup)})" if backup else ""
            console.print(f"  {name:<12} {done:<14} {_terminal(path)}{note}")
        except (OSError, ValueError) as exc:
            failed = True
            console.print(f"  [red]{name:<12} refused[/]        {_terminal(exc)}")
    if args.action == "install" and "codex" in names and not args.dry_run:
        console.print("Codex asks you to review and trust a new hook the next time it starts.")
    if failed:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"hook": cmd_hook}

__all__ = ["COMMANDS", "add_hook_parser", "cmd_hook"]
