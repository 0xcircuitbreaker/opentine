"""``tine lineage record|check|graph|why|archive|index`` (0.58): self-modification lineage.

``lineage record --run RUN --key KEY --code-tree D ...`` signs an attestation
whose claim follows ``opentine.lineage.variant`` and files it, with the evals
and promotion decision it cites, in the lineage folder (:mod:`opentine._lineage`).
``lineage check VARIANT`` walks the variant's ancestry over that folder alone
and exits 1 on any ``lineage.*`` finding (:mod:`opentine._lineage_check`).
``graph``, ``why``, ``archive`` and ``index`` read the derived, rebuildable
index over the same folder (:mod:`opentine._cli_lineage_graph`); ``why`` exits 1
when the check refuses the variant.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from opentine._cli_common import _terminal, console
from opentine._cli_errors import USAGE, error
from opentine._lineage import MAX_BYTES, MAX_FILES

SCHEMA = "tine-cli-lineage/1"


def add_lineage_parser(subparsers: argparse._SubParsersAction) -> None:
    lineage = subparsers.add_parser("lineage", help="Signed lineage of self-modifying variants")
    actions = lineage.add_subparsers(dest="lineage_command", required=True)
    record = actions.add_parser("record", help="Sign and file a variant's lineage record")
    check = actions.add_parser("check", help="Check a variant's ancestry and its evidence")
    graph = actions.add_parser("graph", help="Export the variant DAG (DOT or JSON)")
    why = actions.add_parser("why", help="Walk a variant to every eval, judge, approver, policy")
    archive = actions.add_parser("archive", help="The population of an archive loop")
    index = actions.add_parser("index", help="Build the derived lineage index")
    for parser in (record, check, graph, why, archive, index):
        parser.add_argument("--repo", default=".", metavar="PATH", help="v3 repository")
        parser.add_argument("--dir", metavar="DIR", help="Lineage folder (REPO/.tine/lineage)")
        parser.add_argument("--json", action="store_true", help="Machine-readable output")
    for parser in (check, graph, why, archive, index):
        parser.add_argument(
            "--max-files",
            type=int,
            default=MAX_FILES,
            metavar="N",
            help=f"Refuse a lineage folder over N files ({MAX_FILES})",
        )
        parser.add_argument(
            "--max-bytes",
            type=int,
            default=MAX_BYTES,
            metavar="N",
            help=f"Refuse a lineage folder over N bytes ({MAX_BYTES})",
        )
    for parser in (check, why):
        parser.add_argument(
            "--promotion-policy",
            metavar="TOML",
            help="Also pin eval signers to this policy's eval_signers",
        )
    for parser in (graph, why, archive, index):
        parser.add_argument("--no-refresh", action="store_true",
                            help="Use the index as is, even when stale")  # fmt: skip
    check.add_argument("variant", help="The variant id (sha256:HEX)")
    record.add_argument("--run", required=True, metavar="RUN", help="The mutation run")
    record.add_argument("--key", metavar="KEY", help="Ed25519 private key that signs")
    for name in ("code-tree", "prompt", "config", "weights"):
        record.add_argument(f"--{name}", metavar="DIGEST", help=f"The variant's {name} sha256:")
    record.add_argument("--parent", action="append", default=[], metavar="VARIANT",
                        help="A parent variant id; repeatable")  # fmt: skip
    record.add_argument("--eval", action="append", default=[], metavar="DIR",
                        help="A justifying signed eval folder; repeatable")  # fmt: skip
    record.add_argument("--selector", default="", help="What selected this variant")
    record.add_argument("--decision", metavar="FILE", help="The promotion decision.json")
    record.add_argument("--policy", metavar="HEX", help="Promotion policy sha256")
    record.add_argument("--loop", metavar="LOOP", help="Refuse when LOOP is stopped")
    record.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    graph.add_argument("--format", choices=("dot", "json"), default="dot", help="Output format")
    for parser in (graph, archive):
        parser.add_argument("--loop", metavar="LOOP", help="Only this loop's variants")
    why.add_argument("variant", help="The variant id (sha256:HEX)")
    why.add_argument("--max-depth", type=int, metavar="N", help="Stop N parents up")
    why.add_argument("--max-nodes", type=int, default=10000, metavar="N",
                     help="Stop after N ancestors and mark the walk truncated")  # fmt: skip
    archive.add_argument("--signed", action="store_true", help="Only verified records")
    index.add_argument("--rebuild", action="store_true", help="Delete and rebuild the index")


def _folder(args: argparse.Namespace) -> Path:
    from opentine._lineage import FOLDER

    return Path(args.dir) if args.dir else Path(args.repo) / FOLDER


def _record(args: argparse.Namespace) -> dict:
    from opentine._lineage import record
    from opentine._signing_keys import ed25519_private_from_file

    if not args.key:
        raise error("lineage record needs --key: a record is signed with an Ed25519 key",
                    USAGE, prefix="lineage: ")  # fmt: skip
    key = ed25519_private_from_file(args.key, signer=False)
    artifacts = {"code_tree": args.code_tree, "prompt": args.prompt, "config": args.config,
                 "weights": args.weights}  # fmt: skip
    row = record(key, run=args.run, artifacts=artifacts, store=_folder(args),
                 parents=args.parent, evals=[Path(e) for e in args.eval],
                 selector=args.selector, decision=Path(args.decision) if args.decision else None,
                 policy=args.policy, loop=args.loop, repo_path=Path(args.repo),
                 at=args.at)  # fmt: skip
    return {"ok": True, **row}


def trust(args: argparse.Namespace) -> dict | None:
    """The eval-signer trust for check and why (``None``: unpinned)."""
    from opentine._lineage_trust import load_trust

    policy = getattr(args, "promotion_policy", None)
    return load_trust(Path(args.repo), Path(policy) if policy else None)


def _row(args: argparse.Namespace) -> dict:
    from opentine._cli_lineage_graph import body
    from opentine._lineage_check import check, read_folder

    if args.lineage_command == "record":
        return _record(args)
    files = read_folder(_folder(args), max_files=args.max_files, max_bytes=args.max_bytes)
    if args.lineage_command == "check":
        return check(files, args.variant, trust(args))
    return body(args, _folder(args), files)


def _print(args: argparse.Namespace, row: dict) -> None:
    from opentine._cli_lineage_graph import text
    from opentine._lineage_trust import UNPINNED_WARNING

    command = args.lineage_command
    if command == "graph":  # DOT verbatim: no wrapping, no markup
        from opentine._lineage_index import dot

        sys.stdout.write(dot(row))
    elif command == "record":
        console.print(_terminal(f"RECORDED {row['variant']} {row['record']}"), markup=False)
    elif command == "check":
        verdict = "OK" if row["ok"] else "REFUSED"
        console.print(_terminal(f"{verdict} {row['variant']} ({len(row['ancestors'])} "
                                "ancestors)"), markup=False)  # fmt: skip
        if row["signers"] == "unpinned":
            console.print(_terminal(f"  warning: {UNPINNED_WARNING}"), markup=False)
        for item in row["findings"]:
            console.print(_terminal(f"  {item['code']} {item['variant']}: {item['detail']}"),
                          markup=False)  # fmt: skip
    else:
        console.print(_terminal(text(args, row)), markup=False)


def cmd_lineage(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._key_store import PassphraseUnavailable
    from opentine._signing_keys import SignatureError

    try:
        row = _row(args)
    except (PassphraseUnavailable, SignatureError, OSError, ValueError, KeyError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        raise error(message, prefix="lineage: ") from exc
    command = args.lineage_command
    if args.json or (command == "graph" and args.format == "json"):
        out = {"command": f"lineage {command}", "schema": SCHEMA, **row}
        emit(out)
    else:
        _print(args, row)
    if row.get("ok") is False:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"lineage": cmd_lineage}

__all__ = ["COMMANDS", "SCHEMA", "add_lineage_parser", "cmd_lineage"]
