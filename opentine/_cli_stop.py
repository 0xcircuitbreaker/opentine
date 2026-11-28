"""``tine stop init|issue|continue|status|compliance``: a fleet-wide fail-closed stop.

``init --channel DIR --fleet F`` creates the fleet's stop channel (a signed
transparency log, :mod:`opentine._stop_channel`) or reads an existing one, and
installs the stop policy in this repository (:mod:`opentine._stop_policy`):
from then on ``tine record`` and ``tine run`` here need a fresh continue proof
before each step and halt when they cannot get one. ``issue`` signs and
publishes a fleet stop; ``continue`` signs one continue proof per ``--run``
(both need a pinned ``stopper`` or ``policy`` key, :mod:`opentine._stop_ops`).
``status`` reports what a runner of ``--run`` would decide now and exits 1 when
it would halt. ``compliance`` lists signed stop-compliance records
(:mod:`opentine._stop_compliance`); a non-compliant one is advisory unless
``--strict``.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

SCHEMA = "tine-cli-stop/1"
VERBS = ("init", "issue", "continue", "status", "compliance")


def add_stop_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._stop_policy import DEFAULT_SKEW_S, DEFAULT_WATCHDOG_S, DEFAULT_WINDOW_S

    parser = subparsers.add_parser("stop", help="Fleet-wide fail-closed stop (signed proofs)")
    verbs = parser.add_subparsers(dest="stop_command", required=True)
    init = verbs.add_parser("init", help="Create or join a stop channel; install the policy")
    issue = verbs.add_parser("issue", help="Sign and publish a fleet stop")
    cont = verbs.add_parser("continue", help="Sign and publish continue proofs")
    status = verbs.add_parser("status", help="Whether a run may act now")
    comp = verbs.add_parser("compliance", help="Signed stop-compliance records")
    for verb in (init, issue, cont):
        verb.add_argument("--channel", required=True, metavar="DIR", help="Stop channel directory")
        verb.add_argument("--fleet", required=True, metavar="FLEET", help="Fleet id")
    init.add_argument("--vkey", metavar="VKEY", help="Expected channel verifier key")
    init.add_argument("--window", type=int, default=DEFAULT_WINDOW_S, metavar="S",
                      help=f"Freshness window in seconds (default {DEFAULT_WINDOW_S})")  # fmt: skip
    init.add_argument("--skew", type=int, default=DEFAULT_SKEW_S, metavar="S",
                      help=f"Allowed clock skew in seconds (default {DEFAULT_SKEW_S})")  # fmt: skip
    init.add_argument("--watchdog", type=int, default=DEFAULT_WATCHDOG_S, metavar="S",
                      help=f"Watchdog interval (default {DEFAULT_WATCHDOG_S} s)")  # fmt: skip
    issue.add_argument("--reason", default="", help="Why the fleet is stopped")
    cont.add_argument("--run", action="append", required=True, metavar="RUN",
                      help="Run id (repeatable)")  # fmt: skip
    cont.add_argument("--window", type=int, default=DEFAULT_WINDOW_S, metavar="S",
                      help="Window the proof claims (the runner uses the smaller)")  # fmt: skip
    for verb in (issue, cont):
        verb.add_argument("--key", required=True, metavar="KEY", help="Stopper or policy key")
    status.add_argument("--run", metavar="RUN", help="The run to decide for")
    comp.add_argument("--strict", action="store_true", help="A non-compliant halt exits 1")
    for verb in (init, issue, cont, status, comp):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _init(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str], int]:
    from opentine import _stop_channel, _stop_policy

    vkey = _stop_channel.init(Path(args.channel), args.fleet)
    if args.vkey and args.vkey.strip() != vkey:
        raise ValueError("the channel's verifier key is not the expected --vkey")
    doc = _stop_policy.make(args.fleet, Path(args.channel).as_posix(), vkey,
                            window_s=args.window, skew_s=args.skew,
                            watchdog_s=args.watchdog)  # fmt: skip
    held = _stop_policy.install(repo, doc)
    return {"policy": doc, "held": held}, [f"fleet {args.fleet}: stop policy installed; "
                                           f"channel key {vkey}"], 0  # fmt: skip


def _body(args: argparse.Namespace, repo: Any, now: int) -> tuple[dict[str, Any], list[str], int]:
    from opentine import _stop_compliance, _stop_ops, _stop_policy

    verb = args.stop_command
    if verb == "init":
        return _init(args, repo)
    if verb in ("issue", "continue"):
        from opentine._key_hygiene import ed25519_private

        key = ed25519_private(args.key)
        if verb == "issue":
            row = _stop_ops.issue_stop(repo, Path(args.channel), args.fleet, key,
                                       reason=args.reason, now_ms=now)  # fmt: skip
            return {"entries": [row]}, [f"fleet {args.fleet} stopped ({row['attestation']})"], 0
        rows = _stop_ops.issue_continue(repo, Path(args.channel), args.fleet, args.run, key,
                                        window_s=args.window, now_ms=now)  # fmt: skip
        return {"entries": rows}, [f"continue {r['claim']['run']} seq {r['claim']['seq']} "
                                   f"({r['attestation']})" for r in rows], 0  # fmt: skip
    if verb == "compliance":
        rows = _stop_compliance.report(repo)
        bad = [r for r in rows if not r["compliant"]]
        lines = [f"{r['record']}: {r['run']} {r['code']} "
                 f"{'compliant' if r['compliant'] else r['problem']}" for r in rows]  # fmt: skip
        code = 1 if args.strict and bad else 0
        return {"records": rows, "ok": not bad}, lines or ["no stop-compliance records"], code
    policy = _stop_policy.load(repo)
    if policy is None:
        return ({"fleet": None, "channel": None, "window_s": None, "run": args.run, "ok": True,
                 "code": None, "message": "no stop policy is installed", "proof": None,
                 "stops": [], "runs": [], "checkpoint": None},
                ["no stop policy is installed"], 0)  # fmt: skip
    body = _stop_ops.status(repo, policy, args.run, now)
    line = f"fleet {policy['fleet']}: " + ("ok" if body["ok"] else f"{body['code']}: "
                                           f"{body['message']}")  # fmt: skip
    return body, [line], 0 if body["ok"] else 1


def cmd_stop(args: argparse.Namespace) -> None:
    from opentine._cli_common import _terminal, console
    from opentine._cli_errors import error
    from opentine._cli_ingest import _now
    from opentine._cli_json import emit
    from opentine.repo import Repo

    try:
        repo = Repo.open(args.repo)
        body, lines, code = _body(args, repo, _now(args))
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix="stop: ") from exc
    if args.json:
        emit({"command": f"stop {args.stop_command}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if code:
        raise SystemExit(code)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"stop": cmd_stop}

__all__ = ["COMMANDS", "SCHEMA", "VERBS", "add_stop_parser", "cmd_stop"]
