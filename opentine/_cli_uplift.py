"""``tine uplift suite|record|horizon|compare`` (0.73): uplift and capability trends.

``suite`` prints a suite file's digest and, with ``--key``, signs and holds it;
``record`` signs and holds one baseline, run or speed record
(:mod:`opentine._uplift`); ``horizon`` and ``compare`` compute from the suite's
export (:mod:`opentine._uplift_export`, :mod:`opentine._uplift_report`), read
from the repository or from ``--from FILE``, and exit 1 on a ``fail:`` finding
(``--strict``: on an advisory too).
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-uplift/1"
_BOOL = {"yes": True, "no": False}


def _report_args(verb: argparse.ArgumentParser) -> None:
    source = verb.add_mutually_exclusive_group(required=True)
    source.add_argument("--suite", metavar="DIGEST", help="Suite digest (sha256:...)")
    source.add_argument("--from", dest="from_export", metavar="FILE", help="Recompute from export")
    verb.add_argument("--export", metavar="FILE", help="Also write the export to FILE")
    verb.add_argument("--seed", type=int, default=0, help="Bootstrap seed (default 0)")
    verb.add_argument("--resamples", type=int, default=2000, help="Bootstrap resamples")
    verb.add_argument("--alpha", default="0.05", help="Interval alpha (default 0.05)")
    verb.add_argument("--strict", action="store_true", help="Advisory findings block too")
    verb.add_argument(
        "--bootstrap",
        default="naive",
        choices=("naive", "cluster"),
        help="naive: resample points; cluster: clusters, then points (0.86)",
    )
    verb.add_argument(
        "--cluster-key",
        choices=("task", "subject"),
        help="With --bootstrap cluster: what a cluster is (default task)",
    )


def add_uplift_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._uplift import CONDITIONS, KINDS

    parser = subparsers.add_parser("uplift", help="Uplift suites, records and time horizons")
    verbs = parser.add_subparsers(dest="uplift_command", required=True)
    suite = verbs.add_parser("suite", help="Digest of a suite file; with --key, sign and hold it")
    suite.add_argument("file", metavar="FILE", help="Suite JSON: name, version, scoring, tasks")
    suite.add_argument("--run", metavar="RUN", help="The run the record is attached to")
    suite.add_argument("--key", metavar="KEY", help="A scorer or eval Ed25519 key")
    rec = verbs.add_parser("record", help="Sign and hold one baseline, run or speed record")
    rec.add_argument("--suite", required=True, metavar="DIGEST", help="Suite digest")
    rec.add_argument("--type", dest="record_type", required=True, choices=KINDS)
    rec.add_argument("--task", required=True, metavar="ID", help="Task id in the suite")
    rec.add_argument("--subject", required=True, metavar="ID", help="Person, model or variant")
    rec.add_argument("--condition", required=True, choices=CONDITIONS)
    rec.add_argument("--success", choices=sorted(_BOOL), help="The attempt succeeded")
    rec.add_argument("--minutes", metavar="DECIMAL", help="Measured minutes")
    rec.add_argument("--perceived-minutes", metavar="DECIMAL", help="Perceived minutes (speed)")
    rec.add_argument("--generation", type=int, metavar="N", help="Lineage generation")
    rec.add_argument("--run", required=True, metavar="RUN", help="The run the record is on")
    rec.add_argument("--key", required=True, metavar="KEY", help="A scorer or eval Ed25519 key")
    hor = verbs.add_parser("horizon", help="50%%-success time horizon with a bootstrap interval")
    _report_args(hor)
    hor.add_argument("--condition", default="ai", choices=CONDITIONS)
    hor.add_argument("--subject", metavar="ID", help="Only this subject")
    cmp_ = verbs.add_parser("compare", help="Two groups: success, minutes, perceived speed")
    _report_args(cmp_)
    cmp_.add_argument("--a", required=True, metavar="CONDITION[:SUBJECT]", help="Group A")
    cmp_.add_argument("--b", required=True, metavar="CONDITION[:SUBJECT]", help="Group B")
    for verb in (suite, rec):
        verb.add_argument("--at", metavar="TIME", help="Record time (default now, UTC)")
    for verb in (suite, rec, hor, cmp_):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _run_id(repo: Any, run: str) -> str:
    return run if run.startswith("run:") else repo.load_run(run).id


def _suite(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _uplift
    from opentine._audit_game import now
    from opentine._key_hygiene import ed25519_private

    body = json.loads(Path(args.file).read_bytes())
    problems = _uplift.check_suite(body)
    if problems:
        raise ValueError(f"not a valid suite: {problems[0]}")
    digest = _uplift.suite_digest(body)
    out = {"suite": digest, "tasks": len(body["tasks"]), "record": None, "run": None}
    if args.key is None:
        return out, [digest]
    if not args.run:
        raise ValueError("--key needs --run")
    claim = {"convention": _uplift.SUITE, "digest": digest, "suite": body, "at": args.at or now()}
    run = _run_id(repo, args.run)
    oid = _uplift.record(repo, run, claim, ed25519_private(args.key))
    return {**out, "record": oid, "run": run}, [f"recorded suite {digest} on {run}: {oid}"]


def _record(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _uplift
    from opentine._audit_game import now
    from opentine._key_hygiene import ed25519_private

    claim = {"convention": _uplift.RECORD, "record": args.record_type, "suite": args.suite,
             "task": args.task, "subject": args.subject, "condition": args.condition,
             "success": _BOOL.get(args.success or ""), "minutes": args.minutes,
             "perceived_minutes": args.perceived_minutes, "generation": args.generation,
             "at": args.at or now()}  # fmt: skip
    run = _run_id(repo, args.run)
    oid = _uplift.record(repo, run, claim, ed25519_private(args.key))
    body = {"record": oid, "suite": args.suite, "type": args.record_type, "task": args.task,
            "run": run}  # fmt: skip
    return body, [f"recorded {args.record_type} {args.task} on {run}: {oid}"]


def _export(args: argparse.Namespace, repo: Any) -> dict[str, Any]:
    from opentine import _uplift_export

    if args.from_export:
        return _uplift_export.load(args.from_export)
    export = _uplift_export.build(repo, args.suite)
    if args.export:
        Path(args.export).write_bytes(_uplift_export.dump(export))
    return export


def _fit_line(label: str, fit: dict[str, Any]) -> str:
    if fit["status"] != "ok":
        return f"{label}: no horizon ({fit['status']}, {fit['n']} points)"
    ci = f" [{fit['ci'][0]}, {fit['ci'][1]}]" if fit["ci"] else ""
    return f"{label}: horizon {fit['horizon_minutes']} min{ci}, {fit['n']} points"


def _horizon(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine._uplift_report import report_horizon

    body = report_horizon(_export(args, repo), condition=args.condition, subject=args.subject,
                          seed=args.seed, resamples=args.resamples, alpha=args.alpha,
                          strict=args.strict, bootstrap=args.bootstrap,
                          cluster_key=args.cluster_key)  # fmt: skip
    lines = [_fit_line(args.condition, body["fit"])]
    lines += [_fit_line(f"  generation {t['generation']}", t) for t in body["trend"]]
    return body, lines


def _compare(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine._uplift_report import report_compare, selector

    body = report_compare(_export(args, repo), selector(args.a), selector(args.b),
                          seed=args.seed, resamples=args.resamples, alpha=args.alpha,
                          strict=args.strict, bootstrap=args.bootstrap,
                          cluster_key=args.cluster_key)  # fmt: skip
    lines = []
    for name in ("a", "b"):
        g = body[name]
        lines.append(f"{name}: {g['condition']} {g['successes']}/{g['attempts']} solved, "
                     f"perceived/measured {g['perceived_over_measured'] or 'n/a'}")  # fmt: skip
        lines.append(_fit_line(f"   {name}", g["fit"]))
    lines.append(f"b/a minutes on {body['paired_tasks']} paired task(s): "
                 f"{body['b_over_a_minutes'] or 'n/a'}")  # fmt: skip
    return body, lines


_VERBS = {"suite": _suite, "record": _record, "horizon": _horizon, "compare": _compare}


def cmd_uplift(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine.repo import Repo

    verb = args.uplift_command
    try:
        needs_repo = not (verb in ("horizon", "compare") and args.from_export) and not (
            verb == "suite" and args.key is None
        )
        repo = Repo.open(args.repo) if needs_repo else None
        body, lines = _VERBS[verb](args, repo)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"uplift {verb}: ") from exc
    if verb in ("horizon", "compare"):
        lines += [f"{f['code']} {f['oid']}: {f['message']}" for f in body["findings"]]
    if args.json:
        emit({"command": f"uplift {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if verb in ("horizon", "compare") and not body["ok"]:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"uplift": cmd_uplift}

__all__ = ["COMMANDS", "add_uplift_parser", "cmd_uplift"]
