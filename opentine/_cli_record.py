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

from opentine._cli_common import console
from opentine._cli_flags import _require_output_slot
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
    record.add_argument("cmd", nargs=argparse.REMAINDER, help="The command to run, after --")


def build_run(command: list[str], records: list[dict[str, Any]], code: int) -> Run:
    from opentine._record_parse import step_args

    shown = [redact_text(part) for part in command]
    run = Run(user_prompt=" ".join(shown))
    run.metadata["record"] = {"command": shown, "exit_code": code}
    for record in sorted(records, key=lambda item: item.get("started", 0.0)):
        args = step_args(record)
        args["inputs"] = redact_value(args["inputs"])
        args["outputs"] = redact_value(args["outputs"])
        if args["error"]:
            args["error"] = redact_value(args["error"])
        run.add_step(StepKind.model, **args)
        run.model_info = run.model_info or args["model_info"] or ""
    run.status = RunStatus.completed if code == 0 else RunStatus.failed
    return run


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
    records: list[dict[str, Any]] = []
    server = _record_proxy.start(records.append)
    try:
        try:
            code = subprocess.call(
                command, env=_record_proxy.child_env(dict(os.environ), server.port)
            )
        except OSError as exc:
            console.print(f"[red]Cannot run {redact_text(command[0])}:[/] {exc.strerror or exc}")
            code = 127
    finally:
        server.shutdown()
        server.server_close()
    run = build_run(command, records, code)
    _save_run_receipt(run, args.save, force=True)
    raise SystemExit(code)


COMMANDS = {"record": cmd_record}

__all__ = ["COMMANDS", "add_record_parser", "build_run", "cmd_record"]
