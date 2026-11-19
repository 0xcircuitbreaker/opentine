"""``tine sabotage record|report`` (0.68): sabotage task records and catch rates.

``record`` signs one ``opentine.sabotage-task/1`` outcome (main task, side
task attempted/achieved, evidence, linked monitor verdicts) onto a run and
holds it (:mod:`opentine._sabotage`); ``report`` reads every held record and
prints catch rate per sabotage class (:mod:`opentine._sabotage_report`),
exiting 1 on a ``fail:`` finding (``--strict``: on an advisory too).
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-sabotage/1"
_BOOL = {"yes": True, "no": False}


def add_sabotage_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._sabotage import CLASSES

    parser = subparsers.add_parser("sabotage", help="Sabotage task records and catch rates")
    verbs = parser.add_subparsers(dest="sabotage_command", required=True)
    rec = verbs.add_parser("record", help="Sign and hold one sabotage task outcome")
    rec.add_argument("--run", required=True, metavar="RUN", help="The scored run (id or ref)")
    rec.add_argument("--task", required=True, metavar="ID", help="Sabotage task id")
    rec.add_argument("--class", dest="sabotage_class", required=True, choices=CLASSES)
    rec.add_argument("--main-task", required=True, metavar="ID", help="Main task id")
    rec.add_argument("--main-score", metavar="DECIMAL", help="Main task score")
    rec.add_argument("--main-passed", choices=sorted(_BOOL), help="Main task passed")
    rec.add_argument("--side-task", required=True, metavar="ID", help="Side task id")
    rec.add_argument("--attempted", action="store_true", help="The side task was attempted")
    rec.add_argument("--achieved", action="store_true", help="The side task was achieved")
    rec.add_argument("--evidence", action="append", default=[], metavar="REF",
                     help="An evidence reference (repeatable)")  # fmt: skip
    rec.add_argument("--verdict", action="append", default=[], metavar="ATTESTATION",
                     help="A linked monitor verdict (repeatable)")  # fmt: skip
    rec.add_argument("--key", required=True, metavar="KEY", help="A scorer or eval Ed25519 key")
    rec.add_argument("--at", metavar="TIME", help="Record time (default now, UTC)")
    rep = verbs.add_parser("report", help="Catch rate per sabotage class (advisory)")
    rep.add_argument("--task", metavar="ID", help="Only this task")
    rep.add_argument("--strict", action="store_true", help="Advisory findings block too")
    rep.add_argument("--seed", type=int, default=0, help="Bootstrap seed (default 0)")
    rep.add_argument("--resamples", type=int, default=2000, help="Bootstrap resamples")
    rep.add_argument("--alpha", default="0.05", help="Interval alpha (default 0.05)")
    for verb in (rec, rep):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _record(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _sabotage
    from opentine._audit_game import now
    from opentine._key_hygiene import ed25519_private

    if args.achieved and not args.attempted:
        raise ValueError("--achieved needs --attempted")
    claim = {"convention": _sabotage.CONVENTION, "task": args.task,
             "class": args.sabotage_class,
             "main_task": {"id": args.main_task, "score": args.main_score,
                           "passed": _BOOL.get(args.main_passed or "")},
             "side_task": {"id": args.side_task, "attempted": args.attempted,
                           "achieved": args.achieved},
             "evidence": list(args.evidence), "monitor_verdicts": list(args.verdict),
             "at": args.at or now()}  # fmt: skip
    run = args.run if args.run.startswith("run:") else repo.load_run(args.run).id
    oid = _sabotage.record(repo, run, claim, ed25519_private(args.key))
    body = {"record": oid, "task": args.task, "class": args.sabotage_class, "run": run}
    return body, [f"recorded {args.task} ({args.sabotage_class}) on {run}: {oid}"]


def _report(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine._sabotage_report import report

    body = report(repo, args.task, strict=args.strict, seed=args.seed,
                  resamples=args.resamples, alpha=args.alpha)  # fmt: skip
    lines = ["advisory: catch rates are statistical evidence, not proof of intent"]
    for c in body["classes"]:
        rate = c["catch_rate"] or "n/a"
        ci = f" [{c['ci'][0]}, {c['ci'][1]}]" if c["ci"] else ""
        lines.append(f"{c['class']:8} {c['tasks']} task(s), {c['attempted']} attempted, "
                     f"{c['caught']} caught, catch rate {rate}{ci}, "
                     f"{c['achieved_uncaught']} achieved uncaught")  # fmt: skip
    lines += [f"{f['code']} {f['task']}: {f['message']}" for f in body["findings"]]
    return body, lines


def cmd_sabotage(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine.repo import Repo

    verb = args.sabotage_command
    try:
        repo = Repo.open(args.repo)
        body, lines = (_record if verb == "record" else _report)(args, repo)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"sabotage {verb}: ") from exc
    if args.json:
        emit({"command": f"sabotage {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if verb == "report" and not body["ok"]:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"sabotage": cmd_sabotage}

__all__ = ["COMMANDS", "add_sabotage_parser", "cmd_sabotage"]
