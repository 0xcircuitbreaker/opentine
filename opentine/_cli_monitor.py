"""``tine monitor stop|stops|verdicts|verify|gate`` (0.63): monitor verdicts and stops.

``stop --scope SCOPE --key KEY`` signs and holds a stop token
(:mod:`opentine._monitor_stop`); ``stops`` lists them; ``verdicts`` lists the
held monitor verdicts and whether each verifies; ``verify [--run RUN...]``
checks offline that every blocked or replaced action in the given runs has its
verdict record (:mod:`opentine._monitor_audit`) and exits 1 on a ``fail:``
finding (``--strict``: on an advisory too); ``gate`` is the hook-path monitor
an agent CLI runs before each tool call (:mod:`opentine._monitor_hook`).
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-monitor/1"
AGENTS = ("claude-code", "codex", "gemini", "generic")


def add_monitor_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("monitor", help="Inline monitor verdicts and stop tokens")
    verbs = parser.add_subparsers(dest="monitor_command", required=True)
    stop = verbs.add_parser("stop", help="Sign and hold a stop token (never released)")
    stop.add_argument("--scope", default="*", help="*, agent:NAME or session:ID (default *)")
    stop.add_argument("--key", required=True, metavar="KEY", help="A stopper Ed25519 key")
    stop.add_argument("--reason", default="", help="Why")
    stops = verbs.add_parser("stops", help="List stop tokens")
    verdicts = verbs.add_parser("verdicts", help="List held monitor verdicts")
    verify = verbs.add_parser("verify", help="Every blocked action has a verdict (offline)")
    verify.add_argument(
        "--run",
        action="append",
        default=[],
        metavar="RUN",
        help="A recorded run: a .tine file or a run id/ref (repeatable)",
    )
    verify.add_argument("--strict", action="store_true", help="Advisory findings block too")
    for verb in (stop, stops, verdicts, verify):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")
    gate = verbs.add_parser("gate", help="Hook path: decide one tool call read from stdin")
    gate.add_argument("--config", required=True, metavar="CONFIG", help="Monitor config")
    gate.add_argument("--repo", default=".", metavar="PATH", help="Where verdicts go")
    gate.add_argument("--key", required=True, metavar="KEY", help="Monitor Ed25519 key")
    gate.add_argument("--agent", choices=AGENTS, help="Payload dialect (default generic)")
    gate.add_argument("--fail-closed", action="store_true",
                      help="Block when the payload or config cannot be read")  # fmt: skip


def _runs(repo: Any, names: list[str]) -> list[tuple[str, Any]]:
    from opentine.core import Run

    out = []
    for name in names:
        path = Path(name)
        run = Run.load(path) if path.is_file() else repo.load_run(name)
        out.append((name, run))
    return out


def _verdict_rows(repo: Any) -> list[dict[str, Any]]:
    from opentine import _monitor_verdict

    pinned = _monitor_verdict.monitors(repo)
    rows = []
    for oid in _monitor_verdict.held(repo):
        row = _monitor_verdict.verify(repo, oid, pinned)
        claim = row["claim"] if isinstance(row["claim"], dict) else {}
        rows.append({"verdict": oid, "verification": row["verification"],
                     "action": claim.get("action"), "tool": claim.get("tool"),
                     "session": claim.get("session"), "enforced": claim.get("enforced"),
                     "decided_by": claim.get("decided_by")})  # fmt: skip
    return rows


def _body(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str], int]:
    from opentine import _monitor_stop

    verb = args.monitor_command
    if verb == "stop":
        from opentine._key_hygiene import ed25519_private

        token = _monitor_stop.stop(repo, args.scope, ed25519_private(args.key), reason=args.reason)
        state = _monitor_stop.verify_token(repo, token, args.scope)
        row = {"scope": args.scope, "token": token, "verification": state}
        return {"stops": [row]}, [f"stopped {args.scope}: {token} ({state})"], 0
    if verb == "stops":
        rows = _monitor_stop.tokens(repo)
        return {"stops": rows}, [f"{r['scope']}: {r['token']} ({r['verification']})"
                                 for r in rows] or ["no stop tokens"], 0  # fmt: skip
    if verb == "verdicts":
        rows = _verdict_rows(repo)
        lines = [f"{r['verdict']} {r['action']} {r['tool']} ({r['verification']})" for r in rows]
        return {"verdicts": rows}, lines or ["no held verdicts"], 0
    from opentine._monitor_audit import audit

    body = audit(repo, _runs(repo, args.run))
    found = body["findings"]
    blocking = [f for f in found if f["level"] == "fail" or args.strict]
    body.update(ok=not blocking, strict=args.strict, blocking=len(blocking))
    lines = [f"{body['verdicts']} held verdict(s); {body['blocked_actions']} blocked and "
             f"{body['replaced_actions']} replaced action(s) checked"]  # fmt: skip
    lines += [f"  {f['code']}: {f['message']}" for f in found]
    return body, lines, 1 if blocking else 0


def cmd_monitor(args: argparse.Namespace) -> None:
    if args.monitor_command == "gate":
        from opentine._monitor_hook import run

        raise SystemExit(run(args))
    from opentine._cli_json import emit
    from opentine.repo import Repo

    try:
        repo = Repo.open(args.repo)
        body, lines, code = _body(args, repo)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix="monitor: ") from exc
    if args.json:
        emit({"command": f"monitor {args.monitor_command}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if code:
        raise SystemExit(code)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"monitor": cmd_monitor}

__all__ = ["COMMANDS", "add_monitor_parser", "cmd_monitor"]
