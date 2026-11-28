"""``tine label`` (0.89): rubric label queues -- the one human-label system.

* ``init NAME --rubric FILE --key POLICY`` starts a queue with a pinned rubric;
* ``assign NAME --items FILE.jsonl --reviewer KEY... --key POLICY`` assigns items;
* ``reassign NAME --item SHA --from KEY --to KEY --reason TEXT --key POLICY``;
* ``next NAME --reviewer KEY`` lists a reviewer's unlabelled items (never judge output);
* ``submit NAME --item SHA --label L --key REVIEWER`` signs one label;
* ``reveal NAME --judge judge.json --outputs SIGNED.jsonl --key POLICY`` files signed
  judge outcomes (``tine judge classify --key --out``); later labels do not count.

Agreement over a queue is ``tine judge agreement --queue NAME``. See
:mod:`opentine._label_queue` and docs/JUDGES.md.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import fail

SCHEMA = "tine-cli-label/1"
WRITE_VERBS = ("init", "assign", "reassign", "submit", "reveal")


def _key(path: str) -> Any:
    from opentine._signing_keys import ed25519_private_from_file

    return ed25519_private_from_file(path, signer=False)


def _at(args: argparse.Namespace) -> str:
    from opentine._utc import rfc3339_utc

    return args.at or rfc3339_utc(time.time())


def _run(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine import _label_ops as ops

    repo, name, verb = Path(args.repo), args.queue, args.label_command
    if verb == "init":
        row = ops.init(repo, name, Path(args.rubric), _key(args.key), _at(args))
        return row, [f"queue {name}: rubric {row['rubric_sha256'][:16]}"]
    if verb == "assign":
        row = ops.assign(repo, name, Path(args.items), args.reviewer or [], _key(args.key),
                         _at(args))  # fmt: skip
        return row, [f"assigned {row['assigned']} (skipped {row['skipped']}) over "
                     f"{row['items']} item(s)"]  # fmt: skip
    if verb == "reassign":
        row = ops.reassign(repo, name, args.item, args.from_reviewer, args.to, args.reason,
                           _key(args.key), _at(args))  # fmt: skip
        return row, [f"reassigned {args.item[:16]} to {row['to']}"]
    if verb == "submit":
        row = ops.submit(repo, name, args.item, args.label, _key(args.key), _at(args))
        return row, [f"labelled {args.item[:16]} {_terminal(args.label)}"]
    if verb == "reveal":
        row = ops.reveal(repo, name, Path(args.judge), Path(args.outputs), _key(args.key),
                         _at(args))  # fmt: skip
        return row, [f"revealed {row['judge']} at entry {row['seq']}"]
    row = ops.pending(repo, name, args.reviewer)
    return row, [f"{r['item_sha256']}" for r in row["pending"]]


def cmd_label(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._label_queue import LabelError

    verb = args.label_command
    try:
        body, lines = _run(args)
    except LabelError as exc:
        fail(str(exc), 1, prefix=f"label {verb}: ")
    except (OSError, ValueError, KeyError) as exc:
        fail(str(exc), 2, prefix=f"label {verb}: ")
    if args.json:
        emit({"command": f"label {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(line, markup=False, highlight=False)


def add_label_parser(sub: Any) -> None:
    parser = sub.add_parser("label", help="Rubric label queues: signed, assigned human labels")
    verbs = parser.add_subparsers(dest="label_command", required=True)
    init = verbs.add_parser("init", help="Start a queue with a pinned rubric")
    init.add_argument("--rubric", required=True, metavar="FILE", help="{name, labels, ...} JSON")
    assign = verbs.add_parser("assign", help="Assign items to reviewers")
    assign.add_argument("--items", required=True, metavar="FILE.jsonl", help="One item per line")
    assign.add_argument("--reviewer", action="append", metavar="KEY", help="Reviewer key")
    move = verbs.add_parser("reassign", help="Move an item from one reviewer to another")
    move.add_argument("--item", required=True, metavar="SHA256")
    move.add_argument("--from", dest="from_reviewer", required=True, metavar="KEY")
    move.add_argument("--to", required=True, metavar="KEY")
    move.add_argument("--reason", required=True, help="Why (recorded, signed)")
    nxt = verbs.add_parser("next", help="A reviewer's unlabelled items, without judge output")
    nxt.add_argument("--reviewer", required=True, metavar="KEY")
    submit = verbs.add_parser("submit", help="Sign one label")
    submit.add_argument("--item", required=True, metavar="SHA256")
    submit.add_argument("--label", required=True)
    reveal = verbs.add_parser("reveal", help="File a judge's outputs; later labels do not count")
    reveal.add_argument("--judge", required=True, metavar="FILE", help="The judge's judge.json")
    reveal.add_argument(
        "--outputs",
        required=True,
        metavar="FILE.jsonl",
        help="Signed judge outcomes (tine judge classify --key --out)",
    )
    for verb in (init, assign, move, nxt, submit, reveal):
        verb.add_argument("queue", metavar="NAME", help="Queue name (REPO/.tine/labels/NAME)")
        verb.add_argument("--repo", default=".", help="Repository root (default .)")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")
    for verb in (init, assign, move, submit, reveal):
        verb.add_argument("--key", required=True, metavar="KEY", help="Ed25519 key that signs")
        verb.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")


COMMANDS = {"label": cmd_label}

__all__ = ["COMMANDS", "SCHEMA", "add_label_parser", "cmd_label"]
