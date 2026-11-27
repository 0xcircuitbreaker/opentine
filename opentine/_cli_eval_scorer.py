"""``tine eval run --isolate/--contract``, ``tine eval rescore`` and ``tine eval lint`` (0.85).

``--isolate`` runs a ``python:`` scorer in the isolated child
(:mod:`opentine._scorer_isolated`) and pins its closure; ``--expect-closure``
refuses (``scorer.closure-mismatch``) when the closure differs from a pinned one.
``--contract`` binds an evaluator contract (:mod:`opentine._scorer_contract`).
An in-process ``python:``/``plugin:`` run reports ``advisory:scorer.in-process``.
``rescore`` re-runs a recorded isolated scorer and signs agree/disagree
(:mod:`opentine._scorer_rescore`); ``lint`` is the introspection lint
(:mod:`opentine._scorer_lint`).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

RESCORE_SCHEMA = "tine-cli-eval-rescore/1"
LINT_SCHEMA = "tine-cli-eval-lint/1"
VERBS = ("rescore", "lint")


def _limits(run: Any) -> None:
    run.add_argument(
        "--scorer-input",
        action="append",
        default=[],
        metavar="FILE",
        help="A read-only file the isolated scorer may read (repeatable)",
    )
    run.add_argument("--lockfile", metavar="FILE", help="Lockfile whose digest the closure pins")
    run.add_argument("--cpu-seconds", type=int, metavar="N", help="Isolated CPU limit (60)")
    run.add_argument("--memory-mb", type=int, metavar="N", help="Isolated memory limit (2048)")
    run.add_argument("--timeout", type=int, metavar="S", help="Isolated time limit (120)")


def add_run_args(run: Any) -> None:
    run.add_argument(
        "--isolate",
        action="store_true",
        help="Run a python: scorer in an isolated child and pin its closure",
    )
    run.add_argument(
        "--expect-closure",
        metavar="DIGEST",
        help="Refuse unless the isolated scorer's closure is this sha256:",
    )
    run.add_argument("--contract", metavar="FILE", help="opentine.scorer-contract/1 to enforce")
    _limits(run)


def add_verbs(verbs: Any) -> None:
    again = verbs.add_parser("rescore", help="Re-run an isolated eval's scorer; sign agreement")
    again.add_argument("eval_dir", metavar="DIR")
    again.add_argument("--dataset", required=True, metavar="DATASET.jsonl")
    again.add_argument("--outputs", metavar="FILE.jsonl", help="{id, output} lines to re-score")
    again.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key that signs")
    again.add_argument("--out", metavar="FILE", help="Write the signed report here")
    again.add_argument("--created-at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    _limits(again)
    lint = verbs.add_parser("lint", help="Flag code that inspects its call stack or the grader")
    lint.add_argument("files", nargs="+", metavar="FILE.py")
    lint.add_argument(
        "--grader",
        action="append",
        default=[],
        metavar="PATH",
        help="A grader or scorer path whose name must not appear (repeatable)",
    )
    lint.add_argument("--strict", action="store_true", help="Exit 1 on any finding")
    for verb in (again, lint):
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _bounds(args: argparse.Namespace) -> dict[str, int]:
    given = {"cpu_seconds": args.cpu_seconds, "memory_mb": args.memory_mb,
             "timeout_seconds": args.timeout}  # fmt: skip
    for name, value in given.items():
        if value is not None and value < 1:
            raise ValueError(f"--{name.replace('_', '-')} is at least 1")
    return {name: value for name, value in given.items() if value is not None}


def build(args: argparse.Namespace, parse: Any) -> tuple[Any, list[dict[str, str]]]:
    """The scorer ``eval run`` uses, and its advisories."""
    from opentine._scorer_isolated import isolated

    if args.isolate:
        scorer = isolated(args.scorer, inputs=[Path(p) for p in args.scorer_input],
                          limits=_bounds(args),
                          lockfile=Path(args.lockfile) if args.lockfile else None,
                          expect=args.expect_closure)  # fmt: skip
        advisories = []
    else:
        if args.expect_closure or args.scorer_input:
            raise ValueError("--expect-closure and --scorer-input need --isolate")
        scorer = parse()
        advisories = []
        if scorer.id in ("python", "plugin"):
            advisories.append({"code": "advisory:scorer.in-process",
                               "detail": "the scorer ran inside the signing process; "
                                         "--isolate runs it in a child"})  # fmt: skip
    if args.contract:
        from opentine._scorer_contract import bind, load

        if scorer.id == "llm-judge":
            raise ValueError("--contract does not apply to llm-judge scorers")
        contract, digest = load(Path(args.contract))
        scorer = bind(scorer, contract, digest)
    return scorer, advisories


def run_verb(args: argparse.Namespace) -> dict[str, Any]:
    if args.eval_command == "lint":
        from opentine._scorer_lint import lint

        row = lint([Path(p) for p in args.files], [Path(p) for p in args.grader])
        return {"schema": LINT_SCHEMA, "ok": not (args.strict and row["findings"]), **row}
    from opentine._eval_dataset import read_jsonl
    from opentine._scorer_rescore import rescore
    from opentine._signing_keys import ed25519_private_from_file

    outputs = None
    if args.outputs:
        from opentine._json_shallow import loads

        lines = Path(args.outputs).read_bytes().decode("utf-8").splitlines()
        outputs = {str(row["id"]): row for row in (loads(x) for x in lines if x.strip())}
    key = ed25519_private_from_file(args.key, signer=False)
    report = rescore(Path(args.eval_dir), read_jsonl(Path(args.dataset)), outputs, key=key,
                     inputs=[Path(p) for p in args.scorer_input],
                     lockfile=Path(args.lockfile) if args.lockfile else None,
                     at=args.created_at)  # fmt: skip
    path = None
    if args.out:
        from opentine._canon import atomic_write_text

        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        atomic_write_text(Path(args.out), text, newline="\n")
        path = Path(args.out).as_posix()
    return {"schema": RESCORE_SCHEMA, "ok": report["verdict"] == "agree", "report": report,
            "path": path}  # fmt: skip


def human(row: dict[str, Any]) -> None:
    from opentine._cli_common import console

    if row.get("schema") == LINT_SCHEMA:
        for item in row["findings"]:
            console.print(f"{item['file']}:{item['line']}: {item['code']} {item['detail']}",
                          highlight=False, markup=False)  # fmt: skip
        console.print(f"{len(row['findings'])} finding(s) in {row['files']} file(s)",
                      highlight=False, markup=False)  # fmt: skip
        return
    report = row["report"]
    console.print(f"{report['verdict'].upper()}: {report['agreed']}/{len(report['rows'])} item(s) "
                  f"re-scored the same; closure {'same' if report['closure_agree'] else 'changed'}",
                  highlight=False, markup=False)  # fmt: skip


__all__ = ["LINT_SCHEMA", "RESCORE_SCHEMA", "VERBS", "add_run_args", "add_verbs", "build",
           "human", "run_verb"]  # fmt: skip
