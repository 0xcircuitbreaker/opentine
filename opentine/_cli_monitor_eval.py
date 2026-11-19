"""``tine monitor backtest|collusion`` (0.63): control evaluations offline.

Registered under ``tine monitor`` by :mod:`opentine._cli_monitor`.

``backtest MONITOR --runs FILE`` replays recorded trajectories against a rule
monitor and reports catch rate, false-positive rate and the decision diff
against the recorded online verdicts (:mod:`opentine._monitor_backtest`);
``--require-reproduced`` exits 1 when a verdict from the same monitor digest
is not reproduced byte for byte. ``collusion MONITOR --runs FILE`` runs the
untrusted-monitor vs untrusted-policy harness (:mod:`opentine._monitor_collusion`);
its findings are advisory only and ``--log FILE`` appends the result as one
JSON line.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-monitor/1"
GROUPS = ("captured", "redacted", "unavailable")
EVAL_VERBS = ("backtest", "collusion")


def add_eval_parsers(verbs: argparse._SubParsersAction) -> None:
    back = verbs.add_parser("backtest", help="Replay recorded trajectories against a monitor")
    back.add_argument("--visibility", metavar="STATE",
                      help="Only trajectories whose steps all have this state")  # fmt: skip
    back.add_argument("--require-reproduced", action="store_true",
                      help="Exit 1 unless same-monitor verdicts reproduce exactly")  # fmt: skip
    coll = verbs.add_parser("collusion", help="Untrusted monitor vs untrusted policy (advisory)")
    coll.add_argument("--reference", metavar="MONITOR", help="A trusted reference monitor spec")
    coll.add_argument("--margin", type=float, default=0.2, help="Catch-rate gap (default 0.2)")
    coll.add_argument("--min-samples", type=int, default=5, metavar="N",
                      help="Attacks needed on each side (default 5)")  # fmt: skip
    coll.add_argument("--log", metavar="FILE", help="Append the result as one JSON line")
    for p in (back, coll):
        p.add_argument("monitor", metavar="MONITOR", help="Monitor spec (JSON)")
        p.add_argument("--runs", action="append", required=True, metavar="FILE",
                       help="Recorded trajectories (JSON Lines); repeatable")  # fmt: skip
        p.add_argument("--json", action="store_true", help="Machine-readable output")


def _row(args: argparse.Namespace) -> dict:
    from opentine._monitor_backtest import backtest, read_trajectories
    from opentine._monitor_rule import canonical, load

    monitor = load(args.monitor)
    runs = read_trajectories(args.runs)
    if args.monitor_command == "backtest":
        if args.visibility is not None:
            parts = args.visibility.split("+")
            if any(p not in GROUPS for p in parts) or parts != sorted(set(parts)):
                raise ValueError("--visibility is a sorted '+'-joined set of " + ", ".join(GROUPS))
        row = backtest(monitor, runs, visibility=args.visibility)
        # Vacuous success is refused: stripped verdicts must not pass the check.
        proven = row["bit_identical"] and row["counts"]["reproduced"] > 0
        row["ok"] = proven or not args.require_reproduced
        return row
    from opentine._monitor_collusion import collusion

    reference = load(args.reference) if args.reference else None
    row = collusion(monitor, runs, reference=reference, margin=args.margin,
                    min_samples=args.min_samples)  # fmt: skip
    row["log"] = None
    if args.log:
        with open(args.log, "ab") as handle:
            handle.write(canonical({**row, "schema": SCHEMA}) + b"\n")
        row["log"] = Path(args.log).as_posix()
    return row


def _print(row: dict, command: str) -> None:
    if command == "backtest":
        c = row["counts"]
        head = "REPRODUCED" if row["bit_identical"] else "NOT REPRODUCED"
        console.print(_terminal(f"{head} {row['monitor']}: {c['steps']} steps, "
                                f"{c['reproduced']} reproduced, {len(row['diff'])} differ"),
                      markup=False)  # fmt: skip
        for name, m in row["groups"].items():
            r = m["replay"]
            console.print(_terminal(f"  {name}: catch {r['catch_rate']} fpr "
                                    f"{r['false_positive_rate']}"), markup=False)  # fmt: skip
        return
    console.print(_terminal(f"ADVISORY {row['untrusted']['monitor']}: {row['rates']}"),
                  markup=False)  # fmt: skip
    for f in row["findings"]:
        console.print(_terminal(f"  {f['code']}: {f['detail']}"), markup=False)


def run(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit

    try:
        row = _row(args)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise error(exc, prefix="monitor: ") from exc
    command = args.monitor_command
    if args.json:
        emit({"command": f"monitor {command}", "schema": SCHEMA, **row})
    else:
        _print(row, command)
    if row["ok"] is False:
        raise SystemExit(1)


__all__ = ["EVAL_VERBS", "add_eval_parsers", "run"]
