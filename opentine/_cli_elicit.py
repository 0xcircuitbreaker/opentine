"""``tine elicit link|report`` (0.68): elicitation links and the sandbagging report.

``elicit link DRAFT --key KEY`` signs an ``opentine.elicit-link/1`` draft (one
task under one elicitation condition, with its effort record and item scores)
and files it under ``REPO/.tine/elicit/links`` (:mod:`opentine._elicit`).
``elicit report`` reads that folder and reports the capability gap across
conditions and advisory under-performance and score-distribution findings
(:mod:`opentine._elicit_report`). It exits 1 only on a ``fail:elicit.*``
finding (a malformed, badly signed, duplicate or optimizer-signed record);
advisory findings never block unless ``--strict`` (D12).
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-elicit/1"


def add_elicit_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._eval_stats import DEFAULT_RESAMPLES

    parser = subparsers.add_parser("elicit", help="Elicitation links and sandbagging analytics")
    verbs = parser.add_subparsers(dest="elicit_command", required=True)
    link = verbs.add_parser("link", help="Sign and file one task under one condition")
    link.add_argument("draft", metavar="DRAFT", help="opentine.elicit-link/1 draft JSON")
    link.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    link.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default now)")
    rep = verbs.add_parser("report", help="Capability gap and advisory under-performance tests")
    rep.add_argument("--alpha", default="0.01", help="Family-wise level and 1-alpha CIs")
    rep.add_argument("--seed", type=int, default=0, help="Resampling seed (default 0)")
    rep.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES,
                     help=f"Resamples per test ({DEFAULT_RESAMPLES})")  # fmt: skip
    rep.add_argument("--strict", action="store_true", help="Advisory findings block too")
    for verb in (link, rep):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--dir", metavar="DIR", help="Link folder (REPO/.tine/elicit/links)")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _folder(args: argparse.Namespace) -> Path:
    from opentine._elicit import FOLDER

    return Path(args.dir) if args.dir else Path(args.repo) / FOLDER


def _link(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine import _elicit
    from opentine._experiment import load
    from opentine._key_hygiene import ed25519_private

    doc = _elicit.sign(load(args.draft), ed25519_private(args.key), at=args.at)
    path = _elicit.file(doc, _folder(args))
    digest = _elicit.digest(doc)
    body = {"task": doc["task"], "condition": doc["condition"]["name"], "record": digest,
            "signer": doc["signer"], "items": len(doc["items"]),
            "path": path.as_posix()}  # fmt: skip
    return body, [f"linked {doc['task']} under {doc['condition']['name']}: {digest}"]


def _report(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine._elicit import read_folder
    from opentine._elicit_load import load
    from opentine._elicit_report import report
    from opentine._experiment_check import roles

    pinned = roles(args.repo)
    row = report(load(read_folder(_folder(args)), pinned), alpha=args.alpha, seed=args.seed,
                 resamples=args.resamples)  # fmt: skip
    fails = [f for f in row["findings"] if f["level"] == "fail"]
    row = {"ok": not fails and not (args.strict and row["findings"]),
           "signers": "pinned" if pinned["status"] == "pinned" else "unpinned", **row}  # fmt: skip
    lines = [
        f"{row['records']} records, reference {row['reference'] or '-'}, "
        f"alpha {row['alpha']} (Bonferroni over {row['correction']['tests']} tests)"
    ]
    for c in row["conditions"]:
        gap = c["gap"]
        spread = f"gap {gap['delta']} [{gap['ci'][0]}, {gap['ci'][1]}]" if gap else "reference"
        lines.append(f"  {c['name']:<20} {c['cue']:<10} n={c['n']:<5} mean {c['mean']}  "
                     f"{spread}  attempts {c['effort']['attempts']}")  # fmt: skip
    for t in row["tests"]:
        lines.append(f"  {t['test']:<16} {t['suspect']} vs {t['control']}: delta {t['delta']} "
                     f"p {t['p_value']}{'  FLAGGED' if t['flagged'] else ''}")  # fmt: skip
    lines += [f"{f['code']} {f['subject'] or '-'}: {f['message']}" for f in row["findings"]]
    lines.append(row["note"])
    return row, lines


def cmd_elicit(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit

    verb = args.elicit_command
    try:
        body, lines = {"link": _link, "report": _report}[verb](args)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"elicit {verb}: ") from exc
    if args.json:
        emit({"command": f"elicit {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if verb == "report" and not body["ok"]:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"elicit": cmd_elicit}

__all__ = ["COMMANDS", "SCHEMA", "add_elicit_parser", "cmd_elicit"]
