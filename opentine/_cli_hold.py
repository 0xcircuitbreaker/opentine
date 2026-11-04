"""``tine hold add|list|release <oid|ref>``: keep objects from every delete (0.35)."""

from __future__ import annotations

import argparse
import json

from opentine._cli_common import BRAND, _terminal, console


def add_hold_parser(sub: argparse._SubParsersAction) -> None:
    hold = sub.add_parser(
        "hold", help="Keep objects (and all they reach) from gc, prune, rewind and remote deletes"
    )
    actions = hold.add_subparsers(dest="hold_action", required=True)
    for name, text in (
        ("add", "Hold an object id, or the object a ref names now"),
        ("release", "Release the holds added as, or on, this object id or ref"),
        ("list", "List holds"),
    ):
        action = actions.add_parser(name, help=text)
        if name != "list":
            action.add_argument("target", metavar="OID|REF")
        action.add_argument("--repo", default=".")
        action.add_argument("--json", action="store_true")


def cmd_hold(args: argparse.Namespace) -> None:
    from opentine._cli_du import _refuse, _repo
    from opentine.repository import _holds

    try:
        repo = _repo(args.repo)
        if args.hold_action == "add":
            rows = [_holds.add(repo, args.target)]
        elif args.hold_action == "release":
            rows = _holds.release(repo, args.target)
        else:
            rows = _holds.read_holds(_holds.holds_path(repo))
    except (OSError, ValueError) as exc:  # KernelError is a ValueError
        _refuse(exc)
    if args.json:
        print(json.dumps({"action": args.hold_action, "holds": rows}, sort_keys=True))
        return
    verb = {"add": "Held", "release": "Released", "list": "Holds"}[args.hold_action]
    console.print(f"[{BRAND}]# {verb}[/] {len(rows)} hold(s)")
    for row in rows:
        target = "" if row["target"] == row["oid"] else f"  ({_terminal(row['target'])})"
        console.print(f"  {row['oid']}{target}")


HOLD_COMMANDS = {"hold": cmd_hold}
