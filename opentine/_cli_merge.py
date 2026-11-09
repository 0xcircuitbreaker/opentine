"""``tine merge`` and ``tine pick`` (0.47, F2, SPEC 4.19).

``tine merge OURS THEIRS`` writes the deterministic merge of two runs
(:mod:`opentine._merge`): every event of both, one ``merge`` event, and a run
whose ``parents`` are ``[OURS, THEIRS]``. ``--ref`` moves that ref to it by
compare-and-swap. Conflicts (workspace paths both sides changed, a differing
policy manifest) are recorded in the merge event's output and leave the run
``paused``; the command then exits 1. ``tine pick ONTO EVENT...`` copies
events of other runs onto ONTO's tips, each naming its ``picked_from``.

``tine merge-queue`` is :mod:`opentine._cli_merge_queue`. ``--json`` output
follows ``tine-cli-merge-1`` and ``tine-cli-pick-1``.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine._cli_errors import fail
from opentine._cli_json import emit
from opentine._cli_merge_queue import add_merge_queue_parser, cmd_merge_queue


def add_merge_parsers(sub: Any) -> None:
    merge = sub.add_parser("merge", help="Merge two runs into one (deterministic merge run)")
    merge.add_argument("ours", metavar="OURS", help="The run merged into (parents[0]): ref or oid")
    merge.add_argument("theirs", metavar="THEIRS", help="The run merged in: ref or oid")
    pick = sub.add_parser("pick", help="Copy events of other runs onto a run's tips")
    pick.add_argument("onto", metavar="ONTO", help="The run picked onto: ref or oid")
    pick.add_argument("events", nargs="+", metavar="EVENT", help="Event oids, in order")
    for parser in (merge, pick):
        parser.add_argument("--ref", help="Move this ref to the new run (compare-and-swap)")
        parser.add_argument("--repo", default=".")
        parser.add_argument("--json", action="store_true")
    add_merge_queue_parser(sub)


def _fail(command: str, exc: Exception) -> None:
    from opentine._merge import MergeError

    message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
    if isinstance(exc, MergeError):
        message = f"{exc.code}: {exc}"
    fail(str(message), prefix=f"tine {command}: ")


def cmd_merge(args: argparse.Namespace) -> None:
    from opentine._merge import MergeError
    from opentine.kernel import KernelError
    from opentine.repository import Repo
    from opentine.repository._merge_ops import merge_runs

    try:
        body = merge_runs(Repo.open(args.repo), args.ours, args.theirs, ref=args.ref)
    except (MergeError, KernelError, KeyError, OSError, ValueError) as exc:
        _fail("merge", exc)
    ok = not body["conflicts"]
    if args.json:
        emit({"command": "merge", "ok": ok, **body})
    else:
        print(f"merged {body['parents'][1]} into {body['parents'][0]}: {body['run']}")
        for row in body["conflicts"]:
            print(f"conflict ({row['kind']}): {row.get('path') or row.get('name')}")
    if not ok:
        raise SystemExit(1)


def cmd_pick(args: argparse.Namespace) -> None:
    from opentine._merge import MergeError
    from opentine.kernel import KernelError
    from opentine.repository import Repo
    from opentine.repository._merge_ops import pick_events

    try:
        body = pick_events(Repo.open(args.repo), args.onto, list(args.events), ref=args.ref)
    except (MergeError, KernelError, KeyError, OSError, ValueError) as exc:
        _fail("pick", exc)
    if args.json:
        emit({"command": "pick", "ok": True, **body})
    else:
        print(f"picked {len(body['picked'])} event(s) onto {body['forked_from']}: {body['run']}")


COMMANDS = {"merge": cmd_merge, "pick": cmd_pick, "merge-queue": cmd_merge_queue}

__all__ = ["COMMANDS", "add_merge_parsers", "cmd_merge", "cmd_pick"]
