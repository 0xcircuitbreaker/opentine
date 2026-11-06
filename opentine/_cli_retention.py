"""``tine retention show|check``: the retention policy, and what gc would prune (0.39).

``show`` prints the effective policy (``retention.toml`` or the built-in default).
``check`` is a dry run: the unreachable objects default ``tine gc`` would delete
now, and how many it keeps because they are held or still inside their window.
"""

from __future__ import annotations

import argparse
import json

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_errors import fail


def add_retention_parser(sub: argparse._SubParsersAction) -> None:
    retention = sub.add_parser(
        "retention", help="Show the retention policy and dry-run what gc would prune"
    )
    actions = retention.add_subparsers(dest="retention_action", required=True)
    for name, text in (
        ("show", "Print the effective retention policy"),
        ("check", "List the unreachable objects gc would delete now (dry run)"),
    ):
        action = actions.add_parser(name, help=text)
        action.add_argument("--repo", default=".")
        action.add_argument("--json", action="store_true")


def cmd_retention(args: argparse.Namespace) -> None:
    from opentine._retention import RetentionPolicy
    from opentine.repository import Repo
    from opentine.repository._gc_prune import plan

    try:
        repo = Repo.open(args.repo)
        policy = RetentionPolicy.for_repo(repo)
        result = None
        if args.retention_action == "check":
            everything = plan(repo, min_age=0)
            result = plan(repo, min_age=0, retained=policy.retained)
    except (OSError, ValueError) as exc:  # KernelError and RetentionError are ValueErrors
        fail(exc)
    doc: dict = {"action": args.retention_action, "policy": policy.describe()}
    if result is not None:
        doc["prune"] = list(result.candidates)
        doc["retained"] = len(everything.candidates) - len(result.candidates)
        doc["unreachable"] = result.unreachable
    if args.json:
        print(json.dumps(doc, sort_keys=True))
        return
    console.print(
        f"[{BRAND}]# Retention[/] {_terminal(policy.source)}: keep {policy.keep_days:g} day(s)"
    )
    for table in ("refs", "status", "tier"):
        for key, days in getattr(policy, table).items():
            console.print(f"  {table} {_terminal(key)}: {days:g} day(s)")
    if policy.legal_hold:
        console.print(f"  legal hold: {len(policy.legal_hold)} object(s)")
    if result is not None:
        console.print(
            f"[{BRAND}]# Would prune[/] {len(doc['prune'])} of {doc['unreachable']} "
            f"unreachable object(s); {doc['retained']} kept by retention or holds"
        )
        for oid in doc["prune"]:
            console.print(f"  {oid}")


RETENTION_COMMANDS = {"retention": cmd_retention}

__all__ = ["RETENTION_COMMANDS", "add_retention_parser", "cmd_retention"]
