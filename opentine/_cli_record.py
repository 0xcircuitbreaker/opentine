"""``tine record -- CMD [ARGS...]``: record every model call a program makes.

A localhost proxy (:mod:`opentine._record_proxy`) stands in for each provider's
base URL in the child's environment. Calls are forwarded to the real upstream and
streamed back unchanged; each one becomes a ``model`` step of a run saved like
every other ``tine run`` (same ``.tine_runs`` default, ``--save``/``--force``,
receipt and tree). The exit code is the child's own.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path
from typing import Any

from opentine._assurance import proxy_marker, witness_save
from opentine._assurance_cli import add_proxy_parser, cmd_proxy
from opentine._cli_common import console
from opentine._cli_flags import _require_output_slot
from opentine._cli_key import add_key_parser, cmd_key
from opentine._cli_mcp_proxy import add_mcp_proxy_parser
from opentine._cli_mcp_proxy import cmd_mcp_proxy as _cmd_mcp_proxy
from opentine._cli_stop_run import add_stop_args, exit_if_halted, halted_metadata, stop_for_run
from opentine._v4_values import mark_lenient
from opentine.core import Run, RunStatus, StepKind
from opentine.redaction import redact_text, redact_value


def add_record_parser(sub: Any) -> None:
    record = sub.add_parser(
        "record", help="Run a command and record the model calls it makes (local proxy)"
    )
    record.add_argument(
        "--save", metavar="PATH", help="Write the run here instead of .tine_runs/<id>.tine"
    )
    record.add_argument(
        "--force", action="store_true", help="Replace an existing --save destination"
    )
    record.add_argument(
        "--upstream",
        action="append",
        default=[],
        metavar="NAME=URL",
        help="Forward a dialect (openai, anthropic, gemini, azure, ...) to URL",
    )
    record.add_argument(
        "--budget",
        metavar="SUBJECT",
        help="Enforce this subject's budget and model allowlist on every call",
    )
    record.add_argument(
        "--budget-key", metavar="KEY", help="Ed25519 key that signs reservations, spend and denials"
    )
    record.add_argument("--repo", metavar="PATH", help="Repository holding the budget ledger")
    add_stop_args(record)  # 0.91: read only when the repository has a stop policy
    record.add_argument("cmd", nargs=argparse.REMAINDER, help="The command to run, after --")
    add_mcp_proxy_parser(sub)
    add_proxy_parser(sub)
    add_key_parser(sub)


def build_run(
    command: list[str],
    records: list[dict[str, Any]],
    code: int,
    budget: dict[str, Any] | None = None,
) -> Run:
    from opentine._record_parse import step_args

    shown = [redact_text(part) for part in command]
    run = Run(user_prompt=" ".join(shown))
    run.metadata["record"] = {"command": shown, "exit_code": code}
    if budget is not None:  # 0.87: the ledger keys this run's spend by budget["run"]
        run.metadata["record"]["budget"] = budget
    run.metadata["capture"] = proxy_marker("record-proxy")  # a claim; verify checks it
    for record in sorted(records, key=lambda item: item.get("started", 0.0)):
        args = step_args(record)
        args["inputs"] = redact_value(args["inputs"])
        args["outputs"] = redact_value(args["outputs"])
        if args["error"]:
            args["error"] = redact_value(args["error"])
        run.add_step(StepKind.model, **args)
        run.model_info = run.model_info or args["model_info"] or ""
    run.status = RunStatus.completed if code == 0 else RunStatus.failed
    return mark_lenient(run)  # a recorder: one unrepresentable value never loses the run


def cmd_record(args: argparse.Namespace) -> None:
    from opentine import _record_proxy
    from opentine._cli_render import _save_run_receipt

    command = list(args.cmd or [])
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        console.print("[red]Name the command to record: tine record -- CMD [ARGS...][/]")
        raise SystemExit(1)
    if args.save:
        _require_output_slot(Path(args.save), args.force)
    try:
        overrides = _record_proxy.parse_upstreams(list(getattr(args, "upstream", None) or []))
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        raise SystemExit(2) from None
    records: list[dict[str, Any]] = []
    stop = stop_for_run(args, args.repo)
    gate, budget = _budget_gate(args)
    server = _record_proxy.start(records.append, overrides, stop_gate(stop, gate))
    try:
        env = _record_proxy.child_env(dict(os.environ), server.port, server.bases)
        try:
            if stop is None:
                code = subprocess.call(command, env=env)
            else:  # 0.91: one killable tree, watched while it runs
                code = stop.supervised.run(command, env, interval_s=stop.policy["watchdog_s"])
        except OSError as exc:
            console.print(f"[red]Cannot run {redact_text(command[0])}:[/] {exc.strerror or exc}")
            code = 127
    finally:
        server.shutdown()
        server.server_close()
    run = build_run(command, records, code, budget)
    halted = halted_metadata(run, stop, run.metadata["record"])
    if gate is not None and gate.denied:
        console.print(f"[yellow]budget: refused {gate.denied} model call(s); see "
                      f"`tine budget ledger {budget['subject']}`[/]")  # fmt: skip
    output = _save_run_receipt(run, args.save, force=True)
    if not witness_save(run, output):
        console.print("[yellow]Unwitnessed (assurance T0): run `tine proxy keygen` to sign.[/]")
    exit_if_halted(halted)
    raise SystemExit(code)


def stop_gate(stop: Any, gate: Any) -> Any:
    from opentine._stop_runner import StopGate

    return gate if stop is None else StopGate(stop, gate)


def _budget_gate(args: argparse.Namespace) -> tuple[Any, dict[str, Any] | None]:
    """The :class:`opentine._record_budget.RecordBudget` ``--budget`` asks for, if any.

    A subject with no usable repository or key stops here; a ledger that becomes
    unreachable later refuses each call instead (fail closed)."""
    subject = getattr(args, "budget", None)
    if not subject:
        return None, None
    import uuid

    from opentine._budget_policy import subject as check_subject
    from opentine._key_hygiene import ed25519_private
    from opentine._record_budget import RecordBudget
    from opentine.repo import Repo

    if not args.budget_key:
        console.print("[red]--budget needs --budget-key: reservations and denials are signed[/]")
        raise SystemExit(2)
    try:
        check_subject(subject)
        repo = Repo.open(args.repo or ".")
        key = ed25519_private(args.budget_key)
    except Exception as exc:  # noqa: BLE001 - a repo, key or subject error stops before the child
        console.print(f"[red]budget: {exc}[/]")
        raise SystemExit(2) from None
    run = "record:" + uuid.uuid4().hex
    return RecordBudget(repo, subject, key, run=run), {"subject": subject, "run": run}


COMMANDS = {"record": cmd_record, "mcp-proxy": _cmd_mcp_proxy, "proxy": cmd_proxy, "key": cmd_key}

__all__ = ["COMMANDS", "add_record_parser", "build_run", "cmd_record"]
