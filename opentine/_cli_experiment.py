"""``tine experiment sign|check`` and ``tine reproduce`` (0.67).

``experiment sign DRAFT --key KEY`` signs an ``opentine.experiment-manifest/1``
draft (:mod:`opentine._experiment`); ``experiment check FILE`` judges a manifest
(:mod:`opentine._experiment_check`) or a reproduce report and exits 1 on a
``fail:`` finding (``--strict``: on an advisory too). ``reproduce MANIFEST
--sample K`` reruns a seeded sample through a runner and writes a signed
``opentine.reproduce-report/1`` (:mod:`opentine._reproduce`); it exits 1 when
any sampled row disagrees beyond ``--tolerance``.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-experiment/1"
REPRODUCE_SCHEMA = "tine-cli-reproduce/1"


def add_experiment_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("experiment", help="Signed experiment manifests")
    verbs = parser.add_subparsers(dest="experiment_command", required=True)
    sign = verbs.add_parser("sign", help="Sign an experiment manifest draft")
    sign.add_argument("manifest", metavar="DRAFT")
    sign.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    sign.add_argument("--out", metavar="PATH", help="Write here (default: in place)")
    sign.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default now)")
    check = verbs.add_parser("check", help="Judge a manifest or reproduce report offline")
    check.add_argument("manifest", metavar="FILE")
    check.add_argument("--repo", metavar="PATH", help="Repository whose pinned roles apply")
    check.add_argument("--strict", action="store_true", help="Advisory findings block too")
    for verb in (sign, check):
        verb.add_argument("--json", action="store_true", help="Print a JSON object")
    rep = subparsers.add_parser("reproduce", help="Rerun a seeded sample of an experiment")
    rep.add_argument("manifest", metavar="EXPERIMENT", help="Signed experiment manifest")
    rep.add_argument("--sample", required=True, type=int, metavar="K", help="Rows to rerun")
    rep.add_argument("--seed", type=int, help="Selection seed (default: from the manifest)")
    rep.add_argument("--tolerance", default="0", metavar="T", help="Allowed score delta")
    rep.add_argument("--repeats", type=int, default=2, metavar="N", help="Reruns per row")
    rep.add_argument("--runner", default="verdict", metavar="SPEC",
                     help="verdict, FILE.py:FUNC or MODULE:FUNC")  # fmt: skip
    rep.add_argument("--key", required=True, metavar="KEY", help="Ed25519 key signing the report")
    rep.add_argument("--out", metavar="PATH", help="Write the signed report here")
    rep.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default now)")
    rep.add_argument("--json", action="store_true", help="Print a JSON object")


def _sign(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine import _experiment as exp
    from opentine._key_hygiene import ed25519_private

    doc = exp.sign(exp.load(args.manifest), ed25519_private(args.key), at=args.at)
    out = Path(args.out or args.manifest)
    out.write_bytes(exp.dump(doc))
    digest = exp.digest(doc)
    body = {"experiment": doc["experiment"], "manifest": digest, "signer": doc["signer"],
            "rows": len(doc["results"]), "path": out.as_posix()}  # fmt: skip
    return body, [f"signed {doc['experiment']}: {digest} -> {out.as_posix()}"]


def _check(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine import _experiment as exp
    from opentine import _reproduce
    from opentine._experiment_check import check

    doc = exp.load(args.manifest)
    if doc.get("convention") == _reproduce.CONVENTION:
        why = _reproduce.verify_report(doc)
        found = [] if why is None else [{"level": "fail", "code": "fail:experiment.bad-signature",
                                         "row": None, "message": why}]  # fmt: skip
        body = {"ok": not found, "experiment": doc.get("experiment"),
                "manifest": doc.get("manifest"), "signer": doc.get("signer"),
                "rows": len(doc.get("rows") or []), "findings": found,
                "kind": "reproduce-report", "verdict": doc.get("verdict")}  # fmt: skip
    else:
        body = {**check(args.manifest, repo=args.repo, strict=args.strict),
                "kind": "manifest", "verdict": None}  # fmt: skip
    head = f"{'ok' if body['ok'] else 'FAIL':4} {body['kind']} {body['experiment']}"
    lines = [head] + [f"{f['code']} {f['row'] or '-'}: {f['message']}" for f in body["findings"]]
    return body, lines


def _reproduce_body(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine import _experiment as exp
    from opentine import _reproduce
    from opentine._key_hygiene import ed25519_private

    manifest = exp.load(args.manifest)
    bad = exp.problems(manifest)
    why = bad[0] if bad else exp.verify(manifest)
    if why:
        raise ValueError(f"{args.manifest}: not a signed experiment manifest ({why})")
    runner = _reproduce.load_runner(args.runner, Path(args.manifest).parent)
    doc = _reproduce.report(manifest, args.runner, runner, args.sample, seed=args.seed,
                            tolerance=args.tolerance, repeats=args.repeats,
                            key=ed25519_private(args.key), at=args.at)  # fmt: skip
    if args.out:
        Path(args.out).write_bytes(exp.dump(doc))
    lines = [f"{r['id']}: expected {r['expected']} got {', '.join(r['observed'])} "
             f"{'agree' if r['agree'] else 'DISAGREE'}" for r in doc["rows"]]  # fmt: skip
    lines.append(f"{doc['verdict']}: {doc['agreed']}/{len(doc['rows'])} rows within "
                 f"{doc['tolerance']} (seed {doc['selection']['seed']})")  # fmt: skip
    if doc["nondeterministic"]:
        lines.append("nondeterministic: " + ", ".join(doc["nondeterministic"]))
    return {"report": doc, "path": Path(args.out).as_posix() if args.out else None}, lines


def _run(name: str, schema: str, handler: Callable, args: argparse.Namespace) -> dict:
    from opentine._cli_json import emit

    try:
        body, lines = handler(args)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"{name}: ") from exc
    if args.json:
        emit({"command": name, "schema": schema, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    return body


def cmd_experiment(args: argparse.Namespace) -> None:
    verb = args.experiment_command
    body = _run(f"experiment {verb}", SCHEMA, {"sign": _sign, "check": _check}[verb], args)
    if verb == "check" and not body["ok"]:
        raise SystemExit(1)


def cmd_reproduce(args: argparse.Namespace) -> None:
    body = _run("reproduce", REPRODUCE_SCHEMA, _reproduce_body, args)
    if body["report"]["verdict"] != "agree":
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {
    "experiment": cmd_experiment,
    "reproduce": cmd_reproduce,
}

__all__ = ["COMMANDS", "add_experiment_parser", "cmd_experiment", "cmd_reproduce"]
