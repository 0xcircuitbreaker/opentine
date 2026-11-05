"""``tine op log|verify`` and ``tine undo [OP]``: the op log (0.36, ``_oplog``)."""

from __future__ import annotations

import argparse
import json
import sys

from opentine._cli_common import BRAND, _terminal, console


def add_op_parsers(sub: argparse._SubParsersAction) -> None:
    op = sub.add_parser("op", help="Read and verify the op log of ref-moving commands")
    actions = op.add_subparsers(dest="op_action", required=True)
    log = actions.add_parser("log", help="List logged ops, newest first")
    log.add_argument("-n", "--limit", type=int, default=None)
    verify = actions.add_parser(
        "verify", help="Check the op log's tiles, hash chain and signed checkpoint (offline)"
    )
    verify.add_argument("--vkey", help="Pin the checkpoint key (signed-note name+hash+key)")
    undo = sub.add_parser("undo", help="Put back the refs an op moved, as a new op")
    undo.add_argument("op", nargs="?", help="Op id (or prefix, or index); default: the latest")
    undo.add_argument(
        "--force", action="store_true", help="Undo across refs moved by unlogged writers"
    )
    for parser in (log, verify, undo):
        parser.add_argument("--repo", default=".")
        parser.add_argument("--json", action="store_true", help="Emit a JSON object instead")


def _fail(args: argparse.Namespace, exc: Exception, extra: dict | None = None) -> None:
    message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
    if args.json:
        print(json.dumps({"error": message, **(extra or {})}, sort_keys=True))
    print(f"tine {args.command}: {_terminal(message)}", file=sys.stderr)
    raise SystemExit(1) from None


def cmd_op(args: argparse.Namespace) -> None:
    from opentine._cli_du import _repo
    from opentine.repository._oplog import log_root, read_ops
    from opentine.repository._tlog_note import stored_vkey

    try:
        repo = _repo(args.repo)
        ops = read_ops(repo.path, args.vkey if args.op_action == "verify" else None)
        vkey = stored_vkey(log_root(repo.path)) if ops else None
    except (KeyError, OSError, ValueError) as exc:
        _fail(args, exc)
    if args.op_action == "verify":
        report = {"ok": True, "size": len(ops), "vkey": args.vkey or vkey}
        report["pinned"] = bool(args.vkey)
        if args.json:
            print(json.dumps(report, sort_keys=True))
        else:
            console.print(f"[{BRAND}]# Verified[/] op log of {len(ops)} op(s)")
        return
    newest = list(reversed(ops))[: args.limit]
    if args.json:
        print(json.dumps({"ops": newest}, sort_keys=True))
        return
    for op in newest:
        undoes = f" (undoes {op['undoes']})" if op.get("undoes") else ""
        console.print(f"[{BRAND}]{op['id']}[/] {_terminal(op['command'])}{undoes}")
        for row in op["refs"]:
            console.print(f"  {_terminal(row['ref'])}: {row['old'] or '-'} -> {row['new'] or '-'}")


def cmd_undo(args: argparse.Namespace) -> None:
    from opentine._cli_du import _repo
    from opentine._undo import UndoRefused, undo

    try:
        result = undo(_repo(args.repo), args.op, force=args.force)
    except UndoRefused as exc:
        _fail(args, exc, {"problems": exc.problems})
    except (KeyError, OSError, ValueError) as exc:
        _fail(args, exc)
    if args.json:
        print(json.dumps(result, sort_keys=True))
        return
    console.print(f"[{BRAND}]# Undid[/] {result['undone']}: {len(result['refs'])} ref(s) restored")
    for row in result["refs"]:
        console.print(f"  {_terminal(row['ref'])}: {row['old'] or '-'} -> {row['new'] or '-'}")


OP_COMMANDS = {"op": cmd_op, "undo": cmd_undo}
