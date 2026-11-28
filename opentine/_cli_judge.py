"""``tine judge`` (0.89): judge assurance.

* ``classify``      run one label judge, or an ensemble, over items (abstain explicit;
                    an ensemble must be independent: copies of one judge count once;
                    (``--key --out``: signed ``opentine.judge-outcome/1`` lines);
* ``agreement``     human and judge-vs-human agreement over a label queue
                    (``tine label``), recomputed, with bootstrap intervals and floor;
* ``validate``      sign a judge validation: signed adversarial outcomes plus the
                    agreement floor, recomputed from the queue;
* ``independence``  judges, monitors and eval items against the candidate's lineage;
* ``injection``     candidate outputs that address their judge (advisory).

The verbs live in :mod:`opentine._cli_judge_ops`; every input file is untrusted
JSON read through :mod:`opentine._json_shallow`. See docs/JUDGES.md.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any

SCHEMA = "tine-cli-judge/1"
VERBS = ("classify", "agreement", "validate", "independence", "injection")


def _stats(verb: argparse.ArgumentParser) -> None:
    verb.add_argument("--queue", required=True, metavar="NAME", help="Label queue (tine label)")
    verb.add_argument("--floor", help="Lower-bound floor of both statistics (default 0.6)")
    verb.add_argument("--alpha", help="Interval alpha (default 0.05)")
    verb.add_argument("--seed", type=int, help="Bootstrap seed (default 0)")
    verb.add_argument("--resamples", type=int, help="Bootstrap resamples (default 2000)")
    verb.add_argument("--min-items", type=int, help="Items a judge is compared on (default 20)")
    verb.add_argument("--min-coverage", help="Share the judge must decide (default 0.9)")


def add_judge_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._judge_ensemble import AGGREGATES

    parser = subparsers.add_parser("judge", help="Label judges, ensembles, agreement, "
                                   "validation and independence")  # fmt: skip
    verbs = parser.add_subparsers(dest="judge_command", required=True)
    cls = verbs.add_parser("classify", help="Run label judges over items")
    cls.add_argument("--judge", action="append", required=True, metavar="PROVIDER[:MODEL]")
    cls.add_argument("--lineage-of", action="append", default=[], metavar="NAME",
                     help="Declared lineage of each --judge, in order")  # fmt: skip
    cls.add_argument("--labels", required=True, help="Allowed labels, comma-separated")
    cls.add_argument("--items", required=True, metavar="FILE", help="Items (JSONL)")
    cls.add_argument("--outputs", metavar="FILE", help="Outputs (JSONL: item, output)")
    cls.add_argument("--prompt", action="append", metavar="FILE",
                     help="Prompt template of each --judge (default built in)")  # fmt: skip
    cls.add_argument("--rubric", metavar="FILE", help="Rubric text appended to the prompt")
    cls.add_argument("--aggregate", choices=AGGREGATES, default="majority")
    cls.add_argument("--positive", metavar="LABEL", help="Positive label (mean, min)")
    cls.add_argument("--min-independent", type=int, help="Independent groups needed")
    cls.add_argument("--max-abstain", default="0.5", help="Abstaining share that abstains")
    cls.add_argument("--out", metavar="FILE", help="Write outcome rows (JSONL)")
    cls.add_argument("--runs-dir", metavar="DIR", help="Where judge runs are saved")
    cls.add_argument("--key", metavar="KEY", help="Pinned scorer key that signs --out")
    cls.add_argument("--at", metavar="RFC3339", help="Signing time (default now)")
    agr = verbs.add_parser("agreement", help="Human and judge agreement over a label queue")
    _stats(agr)
    agr.add_argument("--judge", metavar="FILE", help="Only this judge (judge.json)")
    agr.add_argument("--strict", action="store_true", help="Exit 1 below a floor")
    val = verbs.add_parser("validate", help="Sign a judge validation")
    _stats(val)
    val.add_argument("--judge", required=True, metavar="FILE", help="Judge provenance (judge.json)")
    val.add_argument("--adversarial", required=True, metavar="FILE",
                     help="Adversarial items (JSONL, each with its expected label)")  # fmt: skip
    val.add_argument("--adversarial-outcomes", required=True, metavar="FILE",
                     help="Signed outcomes on them (tine judge classify --key --out)")  # fmt: skip
    val.add_argument("--max-fooled", type=int, default=0, help="Fooled cases allowed")
    val.add_argument("--key", required=True, metavar="KEY", help="A pinned scorer/policy key")
    val.add_argument("--at", metavar="RFC3339", help="Signing time (default now)")
    ind = verbs.add_parser("independence", help="Judges, monitors, items vs a lineage")
    ind.add_argument("--lineage", required=True, metavar="DIR", help="Lineage folder")
    ind.add_argument("--candidate", required=True, metavar="RUN|VARIANT")
    ind.add_argument("--judge", action="append", default=[], metavar="FILE")
    ind.add_argument("--judge-prompt", action="append", default=[], metavar="FILE")
    ind.add_argument("--family-prompt", action="append", default=[], metavar="FILE")
    ind.add_argument("--monitor", action="append", default=[], metavar="DIGEST[=trusted]")
    ind.add_argument("--items", metavar="FILE", help="Eval items (JSONL)")
    ind.add_argument("--ancestry", metavar="FILE", help="Digest ancestry (JSON)")
    ind.add_argument("--threshold", default="0.8", help="Prompt similarity threshold")
    inj = verbs.add_parser("injection", help="Outputs that address their judge (advisory)")
    inj.add_argument("outputs", metavar="OUTPUTS", help="Outputs (JSONL)")
    inj.add_argument("--strict", action="store_true", help="Exit 1 on a finding")
    for verb in (cls, agr, val, ind, inj):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def cmd_judge(args: argparse.Namespace) -> None:
    from opentine import _cli_judge_ops as ops
    from opentine._cli_common import _terminal, console
    from opentine._cli_errors import error
    from opentine._cli_json import emit

    verb = args.judge_command
    try:
        body, lines, ok = ops.HANDLERS[verb](args)
    except ops.Refused as exc:
        raise error(exc, 1, prefix=f"judge {verb}: ") from exc
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"judge {verb}: ") from exc
    if args.json:
        emit({"command": f"judge {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False, highlight=False)
    if not ok:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"judge": cmd_judge}

__all__: list[Any] = ["COMMANDS", "SCHEMA", "VERBS", "add_judge_parser", "cmd_judge"]
