"""The stop policy's flags and halt handling for ``tine run`` and ``tine record`` (0.91).

``--stop-run ID`` and ``--stop-key KEY`` (or ``$OPENTINE_STOP_RUN`` and
``$OPENTINE_STOP_KEY``) are read only when the repository has a stop policy
(:mod:`opentine._stop_runner`); without one the commands behave as before. A
refused or halted run exits 3 and names its signed compliance record.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine._cli_common import console


def add_stop_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--stop-run", metavar="ID", help="Run id continue proofs name (stop policy)"
    )
    parser.add_argument("--stop-key", metavar="KEY",
                        help="Runner key for the stop-compliance record")  # fmt: skip


def places(args: argparse.Namespace, *extra: Any) -> list[Any]:
    """Every place a command touches whose repository's stop policy applies to it."""
    names = ("repo", "cwd", "save", "autosave", "worktree_dir")
    named = [getattr(args, name, None) for name in names]
    return [p for p in (*extra, *named) if p]


def stop_for_run(args: argparse.Namespace, where: str | None = None) -> Any:
    """The stop runner for *where* and every place *args* names, preflighted."""
    from opentine._stop_runner import HALT_EXIT, StopRefused, open_runner
    from opentine.redaction import redact_text

    try:
        runner = open_runner(places(args, where), getattr(args, "stop_run", None),
                             getattr(args, "stop_key", None))  # fmt: skip
        if runner is not None:
            runner.preflight()
    except StopRefused as exc:
        console.print(redact_text(str(exc)), style="red", markup=False)
        raise SystemExit(HALT_EXIT) from None
    return runner


def guarded(args: argparse.Namespace) -> bool:
    """The start check, then :func:`opentine._stop_tree.supervise` (``True``: all done)."""
    from opentine._stop_tree import supervise

    return supervise(args, stop_for_run(args))


def run_watched(agent: Any, prompt: str, stop: Any) -> Any:
    """``agent.run_sync``; under a stop policy a watchdog re-checks during long steps."""
    if stop is None:
        return agent.run_sync(prompt)
    from opentine._stop_guard import Watchdog

    watchdog = Watchdog(stop.guard, stop.supervised.halt, stop.policy["watchdog_s"]).start()
    try:
        return agent.run_sync(prompt)
    finally:
        watchdog.stop()


def halted_metadata(run: Any, stop: Any, slot: dict[str, Any] | None = None) -> Any:
    """After a halt: sign the compliance record and note it on *run*; else ``None``."""
    from opentine.core import RunStatus

    halted = stop.finish() if stop is not None else None
    if halted is not None:
        claim = halted["claim"]
        target = run.metadata if slot is None else slot
        target["stop"] = {"record": halted["record"], "code": claim["code"],
                          "compliant": claim["compliant"]}  # fmt: skip
        run.status = RunStatus.failed
    return halted


def exit_if_halted(halted: Any) -> None:
    from opentine._stop_runner import HALT_EXIT

    if halted is None:
        return
    claim = halted["claim"]
    console.print(f"stop: halted ({claim['code']}); compliance record {halted['record']}"
                  f"{'' if claim['compliant'] else ' (non-compliant: sent to oversight)'}",
                  style="red", markup=False)  # fmt: skip
    raise SystemExit(HALT_EXIT)


__all__ = [
    "add_stop_args",
    "exit_if_halted",
    "guarded",
    "halted_metadata",
    "run_watched",
    "stop_for_run",
]
