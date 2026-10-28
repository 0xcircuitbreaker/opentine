"""``tine import --fleet``: flag checks and output (see :mod:`opentine._import_fleet`)."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from opentine._cli_common import BRAND, _terminal, console

FLEET_HELP = "Claude Code: one child run per subagent, forked at its spawning step (needs --repo)"


def add_extra_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fleet", action="store_true", help=FLEET_HELP)
    parser.add_argument(
        "--adapter",
        metavar="NAME",
        help="Read SOURCE with this adapter (a built-in, or an allowlisted entry point)",
    )


def check_fleet(args: argparse.Namespace) -> None:
    if not getattr(args, "fleet", False):
        return
    if not args.repo or args.save:
        console.print("[red]--fleet records into a repository: pass --repo PATH and no --save.[/]")
        raise SystemExit(1)


def import_fleet(args, repo, events, ref: str, capture, source_format: str) -> None:
    from opentine._hook_journal import agent_types
    from opentine._import_fleet import fleet_cost, record_fleet

    if source_format != "claude-code-transcript":
        raise ValueError(f"--fleet imports Claude Code sessions, not {source_format}")
    manifest = record_fleet(
        repo, events, ref, capture, source_format, journal=agent_types(repo.path)
    )
    cost = fleet_cost(repo, manifest)
    if getattr(args, "json", False):
        out: dict[str, Any] = {"command": "import", "fleet": manifest, "cost_usd": str(cost)}
        sys.stdout.write(json.dumps(out, sort_keys=True) + "\n")
        return
    console.print(
        f"[{BRAND}]# Imported fleet[/] root {_terminal(manifest['root'])} "
        f"with {len(manifest['members'])} subagent run(s); cost ${cost}"
    )
    for member in manifest["members"]:
        kind = f" ({_terminal(member['agent_type'])})" if member["agent_type"] else ""
        console.print(f"  {_terminal(member['ref'])}{kind} -> {_terminal(member['run_id'])}")


__all__ = ["FLEET_HELP", "add_extra_args", "check_fleet", "import_fleet"]
