"""Argparse wiring and output for ``tine init --auto`` (:mod:`opentine._init_auto`)."""

from __future__ import annotations

import argparse
from typing import Any


def add_init_parser(subparsers: argparse._SubParsersAction) -> None:
    init = subparsers.add_parser("init", help="Initialize a v3 .tine repository")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--bare", action="store_true")
    init.add_argument("--auto", action="store_true",
                      help="Also wire detected agent CLIs, a signing key and capture")  # fmt: skip
    init.add_argument("--push-beside-git", action="store_true",
                      help="With --auto: push runs with git commits (pre-push gate)")  # fmt: skip
    init.add_argument("--dry-run", action="store_true", help="With --auto: show, write nothing")


def cmd_init_auto(args: argparse.Namespace, console: Any) -> None:
    from opentine._cli_common import _terminal
    from opentine._init_auto import run

    if args.bare:
        raise SystemExit("--auto sets up a working repository; drop --bare")
    result = run(args.path, push_beside_git=args.push_beside_git, dry_run=args.dry_run)
    for step in result["steps"]:
        name = step.get("agent") or step["step"]
        detail = step.get("detail") or step.get("path") or ""
        console.print(f"  {name:<12} {step['status']:<16} {_terminal(detail)}", markup=False)
    if result["status"] == "fail":
        raise SystemExit(1)


__all__ = ["add_init_parser", "cmd_init_auto"]
