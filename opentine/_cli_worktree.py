"""``tine worktree add/list/remove/prune``: an isolated directory per branch."""

from __future__ import annotations

import argparse
import json

from opentine._cli_common import BRAND, _terminal, console


def add_worktree_parser(sub: argparse._SubParsersAction) -> None:
    tree = sub.add_parser("worktree", help="Add, list, remove or prune per-branch worktrees")
    actions = tree.add_subparsers(dest="worktree_action", required=True)
    add = actions.add_parser("add", help="Create an isolated directory for a ref or run")
    add.add_argument("path")
    add.add_argument("ref", help="A ref or run the worktree works on")
    add.add_argument("--name", help="Registry name (default: the directory name)")
    add.add_argument(
        "--git",
        nargs="?",
        const="HEAD",
        metavar="COMMIT",
        help="Also make it a detached git worktree of the enclosing checkout",
    )
    actions.add_parser("list", help="List registered worktrees")
    remove = actions.add_parser("remove", help="Remove a worktree and its directory")
    remove.add_argument("name")
    remove.add_argument("--force", action="store_true", help="Also delete files in it")
    actions.add_parser("prune", help="Forget worktrees whose directory is gone")
    for parser in (tree, *actions.choices.values()):
        parser.add_argument("--repo", default=".")
        parser.add_argument("--json", action="store_true")


def cmd_worktree(args: argparse.Namespace) -> None:
    from opentine import _worktree
    from opentine.repo import Repo

    repo = Repo.open(args.repo)
    action = args.worktree_action
    if action == "add":
        result = _worktree.add(repo, args.path, args.ref, name=args.name, git=args.git)
        text = f"Added worktree {result['name']} at {result['path']} ({result['ref']})"
    elif action == "list":
        result = _worktree.list_worktrees(repo)
        if not args.json:
            for row in result:
                where = row.get("path", row.get("detail", ""))
                console.print(f"{_terminal(row['name'])}  {row['state']}  {_terminal(where)}")
            return
    elif action == "remove":
        result = _worktree.remove(repo, args.name, force=args.force)
        text = f"Removed worktree {result['name']} ({result['path']})"
    else:
        result = _worktree.prune(repo)
        text = f"Pruned {len(result)} worktree registration(s)"
    if args.json:
        print(json.dumps({"command": f"worktree {action}", "result": result}, sort_keys=True))
        return
    console.print(f"[{BRAND}]#[/] {_terminal(text)}")


WORKTREE_COMMANDS = {"worktree": cmd_worktree}

__all__ = ["WORKTREE_COMMANDS", "add_worktree_parser", "cmd_worktree"]
