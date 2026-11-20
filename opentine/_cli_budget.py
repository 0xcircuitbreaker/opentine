"""``tine budget sign-policy|apply|record|status|ledger|check|gate`` (0.69).

Budgets cap what a loop or agent (``loop:NAME``, ``agent:NAME``) spends:
tokens, GPU-hours, wall clock, egress bytes and money. ``sign-policy`` writes a
signed ``opentine-budget-policy/1`` (:mod:`opentine._budget_policy`); ``apply``
puts it on the subject's ledger, where it takes effect only if a pinned
``policy``-role key signed any raise (otherwise the attempt is flagged for
oversight); ``record`` appends the recorded cost of runs as signed, held
``spend`` entries (:mod:`opentine._budget_ledger`); ``status`` and ``ledger``
read it; ``check`` decides the next action and exits 1 when it is refused;
``gate`` is the agent-hook form (:mod:`opentine._budget_gate`). See
docs/BUDGETS.md.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-budget/1"
VERBS = ("sign-policy", "apply", "record", "status", "ledger", "check", "gate")


def add_budget_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._budget_policy import LIMITS

    parser = subparsers.add_parser("budget", help="Budget policies and the signed spend ledger")
    verbs = parser.add_subparsers(dest="budget_command", required=True)
    sign = verbs.add_parser("sign-policy", help="Write a signed opentine-budget-policy/1")
    sign.add_argument("subject", metavar="SUBJECT", help="loop:NAME or agent:NAME")
    sign.add_argument("--serial", type=int, required=True, help="Higher than the one in force")
    for name in LIMITS:
        sign.add_argument("--" + name.replace("_", "-"), type=float, metavar="N",
                          help=f"Limit: {name}")  # fmt: skip
    sign.add_argument("--on-limit", choices=("deny", "escalate"), default="deny",
                      help="At the limit: refuse, or refuse and route to oversight")  # fmt: skip
    sign.add_argument("--out", required=True, metavar="PATH", help="Where to write the policy")
    apply = verbs.add_parser("apply", help="Put a signed policy on its subject's ledger")
    apply.add_argument("policy", metavar="PATH", help="An opentine-budget-policy/1 file")
    record = verbs.add_parser("record", help="Append the recorded cost of runs as spend")
    record.add_argument("subject", metavar="SUBJECT", help="loop:NAME or agent:NAME")
    record.add_argument("runs", nargs="+", metavar="RUN", help="Run files or ids")
    record.add_argument("--gpu-hours", type=float, default=0.0, metavar="N",
                        help="GPU-hours the runs used (recorded as given)")  # fmt: skip
    record.add_argument("--egress-bytes", type=int, default=0, metavar="N",
                        help="Bytes the runs sent out (recorded as given)")  # fmt: skip
    rows = [sign, apply, record]
    for verb in ("status", "ledger", "check", "gate"):
        row = verbs.add_parser(verb, help={
            "status": "Policy in force, totals, remaining and findings",
            "ledger": "Every ledger entry in chain order, with totals",
            "check": "Decide the next action (exit 1 when refused)",
            "gate": "Agent hook: refuse the tool call on stdin at the limit"}[verb])  # fmt: skip
        row.add_argument("subject", metavar="SUBJECT", help="loop:NAME or agent:NAME")
        rows.append(row)
    rows[-1].add_argument("--agent", choices=("claude-code", "codex", "gemini", "generic"),
                          default=None, help="Hook dialect (default: generic)")  # fmt: skip
    for row in rows:
        needed = row in (apply, record, sign, rows[-1])
        row.add_argument(
            "--key",
            required=needed,
            metavar="KEY",
            help="Ed25519 private key" + ("" if needed else " (records flags)"),
        )
        row.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        row.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
        if row is not rows[-1]:  # gate answers in the hook's own dialect
            row.add_argument("--json", action="store_true", help="Print a JSON object")


def cmd_budget(args: argparse.Namespace) -> None:
    from opentine._budget_policy import BudgetError
    from opentine._cli_budget_ops import body
    from opentine._cli_json import emit

    if args.budget_command == "gate":
        from opentine import _budget_gate

        now = _now(args)
        raise SystemExit(_budget_gate.run(args, now=lambda: now))
    try:
        out, lines, code = body(args, _now(args))
    except (OSError, ValueError, KeyError, BudgetError) as exc:
        raise error(exc, prefix="budget: ") from exc
    if args.json:
        emit({"command": f"budget {args.budget_command}", "schema": SCHEMA, **out})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if code:
        raise SystemExit(code)


def _now(args: argparse.Namespace) -> int:
    from datetime import datetime

    from opentine._budget_gate import clock_ms

    if not args.at:
        return clock_ms()
    try:
        moment = datetime.strptime(args.at, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        raise error(ValueError(f"--at {args.at!r} is not YYYY-MM-DDTHH:MM:SSZ"),
                    prefix="budget: ") from None  # fmt: skip
    return int(moment.timestamp() * 1000)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"budget": cmd_budget}

__all__ = ["COMMANDS", "SCHEMA", "add_budget_parser", "cmd_budget"]
