"""``tine hook install|uninstall|status``: capture every agent session, zero-config.

``tine hook install --global --repo PATH`` adds one session-end hook to each
agent CLI's own user-level hook file (see :mod:`opentine._cli_hook_agents`), so
every finished Claude Code, Codex or Gemini CLI session is imported into the
repository with ``tine import latest --from-default-location``. ``--agent``
narrows it (repeatable), ``--dry-run`` prints the change instead of making it,
and ``uninstall`` removes only what ``install`` added. Installing twice changes
nothing; a user's other hooks are never edited. ``status`` (no ``--global``
needed) lists the events each CLI has opentine commands on. ``--agent hermes``
only prints a ``config.yaml`` snippet (:mod:`opentine._cli_hook_hermes`).
``tine hook event --repo PATH`` is what the plugin's subagent hooks run: it
journals one payload read from stdin (:mod:`opentine._hook_journal`).
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_hook_agents import (
    AGENTS,
    MARKER,
    read_config,
    with_ours,
    without_ours,
    write_config,
)
from opentine._cli_hook_hermes import hermes


def add_hook_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "hook", help="Install agent-CLI hooks that import every finished session"
    )
    parser.add_argument("action", choices=("install", "uninstall", "status", "event"))
    parser.add_argument(
        "--global", dest="global_", action="store_true",
        help="Edit the user-level hook files (the only scope supported)",
    )  # fmt: skip
    parser.add_argument(
        "--agent", action="append", choices=sorted([*AGENTS, "hermes"]),
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


def _ours_by_event(document: dict) -> list[str]:
    """The hook events holding an opentine command (``MARKER`` or ``hook event``)."""
    hooks = document.get("hooks") if isinstance(document.get("hooks"), dict) else {}
    found = []
    for event, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            inner = group.get("hooks") if isinstance(group, dict) else None
            text = json.dumps(inner) if isinstance(inner, list) else ""
            if MARKER in text or "opentine.cli" in text:
                found.append(str(event))
                break
    return found


def cmd_hook(args: argparse.Namespace) -> None:
    if args.action == "event":  # run by an agent CLI: the payload is on stdin only
        from opentine._hook_journal import run_event

        raise SystemExit(run_event(args.repo))
    if not args.global_ and args.action != "status":
        raise _fail("pass --global: hooks are installed in your user-level agent settings")
    names = args.agent or sorted([*AGENTS, "hermes"])
    repo = _repo(args.repo) if args.action == "install" else None
    failed = False
    for name in names:
        if name == "hermes":
            hermes(args.action, repo)
            continue
        agent = AGENTS[name]
        path = agent.config()
        try:
            document = read_config(path)
            if args.action == "status":
                events = _ours_by_event(document)
                state = ",".join(events) if events else "not installed"
                console.print(f"  {name:<12} {state:<30} {_terminal(path)}", markup=False)
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
