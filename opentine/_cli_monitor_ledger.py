"""``tine monitor run|heartbeat|coverage|validate|suspicion``: monitors as evidence.

Registered under ``tine monitor`` by :mod:`opentine._cli_monitor`.

``run --config C --stream S --key K`` evaluates the stream's pending ingest
batches with the monitor and writes coverage records
(:mod:`opentine._monitor_runner`); ``--follow`` keeps running and signs a
heartbeat every ``--interval`` seconds until interrupted. ``heartbeat`` signs
one heartbeat. ``coverage`` reports the proven fraction of captured events the
monitor evaluated, gaps, config changes, stale heartbeats, the latency SLO and
the operating point (:mod:`opentine._monitor_coverage`); it exits 1 on a
``fail:`` finding (``--strict``: on an advisory too). ``validate`` signs the
monitor's operating point on a labelled set (:mod:`opentine._monitor_validation`).
``suspicion`` lists cumulative-suspicion and doom-loop flags
(:mod:`opentine._monitor_suspicion`), advisory unless ``--strict``.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

LEDGER_VERBS = ("run", "heartbeat", "coverage", "validate", "suspicion")


def add_ledger_parsers(verbs: argparse._SubParsersAction) -> None:
    run = verbs.add_parser("run", help="Evaluate an ingest stream; write coverage records")
    run.add_argument("--follow", action="store_true", help="Keep running; sign heartbeats")
    run.add_argument("--poll", type=float, default=1.0, metavar="S", help="Poll every S s")
    beat = verbs.add_parser("heartbeat", help="Sign one monitor heartbeat")
    for verb in (run, beat):
        verb.add_argument("--interval", type=int, default=60, metavar="S",
                          help="Heartbeat interval in seconds (default 60)")  # fmt: skip
    cover = verbs.add_parser("coverage", help="Proven coverage of captured events (offline)")
    cover.add_argument("--profile", choices=("default", "rsi"), default="default",
                       help="rsi: gaps, staleness and unvalidated thresholds fail")  # fmt: skip
    valid = verbs.add_parser("validate", help="Sign the monitor's operating point")
    valid.add_argument("--labelled", required=True, metavar="FILE",
                       help="JSON Lines with label attack or benign")  # fmt: skip
    susp = verbs.add_parser("suspicion", help="Cumulative suspicion and doom-loop flags")
    susp.add_argument("--stream", action="append", default=[], metavar="S",
                      help="Only these streams (repeatable; default all)")  # fmt: skip
    susp.add_argument("--budget", type=float, default=3.0, help="Summed score (default 3.0)")
    susp.add_argument("--margin", type=float, default=0.1, help="Near-threshold band (0.1)")
    susp.add_argument("--repeats", type=int, default=3, metavar="N", help="Repeats (3)")
    for verb in (run, beat, cover, valid):
        verb.add_argument("--config", required=True, metavar="CONFIG", help="Monitor config")
    for verb in (run, beat, cover):
        verb.add_argument("--stream", required=True, metavar="S", help="Ingest stream")
    for verb in (run, beat, valid):
        verb.add_argument("--key", required=True, metavar="KEY", help="Ed25519 key")
    for verb in (cover, susp):
        verb.add_argument("--strict", action="store_true", help="Advisory findings block too")
    for verb in (run, beat, cover, valid, susp):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _run(args: argparse.Namespace, repo: Any, config: dict[str, Any], now: int) -> tuple:
    from opentine._key_hygiene import ed25519_private
    from opentine._monitor_runner import Runner

    clock = (lambda: now) if args.at else None
    runner = Runner(repo, config, args.stream, ed25519_private(args.key), interval_s=args.interval,
                    **({"clock_ms": clock} if clock else {}))  # fmt: skip
    if args.monitor_command == "heartbeat":
        row = runner.heartbeat()
        return {"heartbeat": row}, [f"heartbeat {row['seq']} ({row['id']})"], 0
    if args.follow:
        import threading

        stop = threading.Event()
        try:
            runner.follow(stop, poll_s=args.poll)
        except KeyboardInterrupt:
            stop.set()
        rows: list[dict[str, Any]] = []
    else:
        rows = runner.once()
    body = {"records": rows, "counts": dict(runner.counts)}
    lines = [f"batch {r['batch_seq']}: {r['evaluated']} evaluated, p95 {r['latency']['p95_ms']} "
             f"ms ({r['id']})" for r in rows] or ["nothing pending"]  # fmt: skip
    return body, lines, 0


def _body(args: argparse.Namespace, repo: Any, now: int) -> tuple[dict[str, Any], list[str], int]:
    from opentine import _monitor_ledger
    from opentine._monitors import load

    verb = args.monitor_command
    if verb == "suspicion":
        from opentine._monitor_suspicion import scan
        from opentine._monitor_verdict import monitors

        chains = [c for c in _monitor_ledger.chains(repo) if not args.stream or c[1] in args.stream]
        body = scan(repo, chains, monitors(repo)[0], budget=args.budget, margin=args.margin,
                    repeats=args.repeats)  # fmt: skip
        code = 1 if args.strict and body["flags"] else 0
        lines = [f"{f['code']}: {f['subject']} ({f['record']})" for f in body["flags"]]
        return {**body, "ok": code == 0}, lines or ["no flags"], code
    config = load(args.config)
    if verb in ("run", "heartbeat"):
        return _run(args, repo, config, now)
    identity = _monitor_ledger.identity(config)
    if verb == "validate":
        from opentine._key_hygiene import ed25519_private
        from opentine._monitor_validation import evaluate, record
        from opentine._utc import rfc3339_utc

        point = evaluate(config, Path(args.labelled).read_bytes())
        row = record(repo, identity, point, ed25519_private(args.key), rfc3339_utc(now / 1000))
        tpr, fpr = row["claim"]["tpr"], row["claim"]["fpr"]
        return row, [f"{identity['id']} at {point['threshold']}: TPR {tpr['value']} "
                     f"{tpr['wilson']}, FPR {fpr['value']} {fpr['wilson']} "
                     f"({row['record']})"], 0  # fmt: skip
    from opentine._monitor_coverage import report

    body = report(repo, args.stream, identity, now_ms=now, profile=args.profile,
                  threshold=config["threshold"])  # fmt: skip
    blocking = [f for f in body["findings"] if f["level"] == "fail" or args.strict]
    body.update(ok=not blocking, strict=args.strict, blocking=len(blocking))
    lines = [f"{identity['id']} on {args.stream}: {body['covered']} captured events covered "
             f"({body['percent']}%)"]  # fmt: skip
    lines += [f"  {f['code']}: {f['message']}" for f in body["findings"]]
    return body, lines, 1 if blocking else 0


def run(args: argparse.Namespace) -> None:
    from opentine._cli_common import _terminal, console
    from opentine._cli_errors import error
    from opentine._cli_ingest import _now
    from opentine._cli_json import emit
    from opentine._cli_monitor import SCHEMA
    from opentine.repo import Repo

    try:
        repo = Repo.open(args.repo)
        body, lines, code = _body(args, repo, _now(args))
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix="monitor: ") from exc
    if args.json:
        emit({"command": f"monitor {args.monitor_command}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if code:
        raise SystemExit(code)


__all__ = ["LEDGER_VERBS", "add_ledger_parsers", "run"]
