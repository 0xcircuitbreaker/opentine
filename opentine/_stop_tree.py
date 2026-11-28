"""A supervised ``tine run`` / ``tine fan-out``: the whole invocation as one killable tree.

0.91 review. ``tine record`` and the reference loop check the stop before
every action, but a harness run, a script run and a fan-out had only the check
at start: once the agent was running nothing could stop it. Under a stop policy
:func:`supervise` now re-runs the very same invocation as a child of
:class:`opentine._stop_supervise.Supervised` (its own process group, the Linux
subreaper, the Windows kill-on-close job object), and the parent only watches:

* every ``watchdog_s`` the parent's :class:`opentine._stop_guard.Watchdog`
  re-reads the stop channel and the continue proof; on a stop, a stale or
  missing proof or an unreachable channel it kills the whole tree, every
  harness, script, fan-out member and grandchild included;
* the child (``$OPENTINE_STOP_SUPERVISED`` names its fleet and run) checks at
  start as before and runs a watchdog of its own that kills its own process
  group, so a forged marker outside a supervisor removes nothing but the
  compliance record (defence in depth, never the only stop);
* when the child is gone the parent signs the compliance record
  (``time_to_halt_ms``, ``residual_processes``) and exits 3; a child that
  failed is re-checked once, so a halt the child's own watchdog made is
  recorded too.

With no stop policy nothing of this runs (D12). ``tine run --model`` is
supervised the same way, but its child keeps the in-process gate and watchdog
(:mod:`opentine._cli_stop_run`) instead of the group kill, so a halt there
refuses the next call and the child signs the record with its counts.
"""

from __future__ import annotations

import os
import signal
import sys
from collections.abc import Callable
from typing import Any

from opentine._stop_guard import Halt, Watchdog

SUPERVISED_ENV = "OPENTINE_STOP_SUPERVISED"


def marker(runner: Any) -> str:
    return f"{runner.policy['fleet']}:{runner.run}"


def child_argv(args: Any) -> list[str]:
    """This invocation again (``-P``: a planted ``opentine/`` in the cwd cannot shadow it)."""
    argv = list(getattr(args, "tine_argv", None) or sys.argv[1:])
    return [sys.executable, "-P", "-m", "opentine.cli", *argv]


def _halt_self(halt: Halt) -> None:  # pragma: no cover - the process is gone after it
    sys.stderr.write(f"stop: halted ({halt.code})\n")
    sys.stderr.flush()
    if os.name != "nt":
        try:
            os.killpg(os.getpgrp(), signal.SIGKILL)
        except OSError:
            pass
    os._exit(137)  # as if killed: the parent re-checks and signs


def supervise(args: Any, runner: Any, *, self_watch: bool = True,
              halt_self: Callable[[Halt], None] | None = None) -> bool:  # fmt: skip
    """``False``: go on in this process (the supervised child). Else never returns.

    *self_watch* ``False`` (``--model``, which halts in process at its next call
    and signs its own record) leaves the child without the group-killing watchdog.
    """
    from opentine import _stop_compliance

    if runner is None:
        return False  # D12
    interval = runner.policy["watchdog_s"]
    if os.environ.get(SUPERVISED_ENV) == marker(runner):
        if self_watch:
            Watchdog(runner.guard, halt_self or (lambda halt: _halt_self(halt)), interval).start()
        return False
    env = {**os.environ, SUPERVISED_ENV: marker(runner)}
    before = len(_stop_compliance.held(runner.repo))
    code = runner.supervised.run(child_argv(args), env, interval_s=interval)
    finish(runner, code, signed=len(_stop_compliance.held(runner.repo)) > before)
    return True  # pragma: no cover - finish exits


def finish(runner: Any, code: int, *, signed: bool = False) -> None:
    """After the child: the compliance record and exit 3 on a halt, else the child's code.

    A child that failed other than by halting with a record of its own (its
    watchdog killed its group, or it exited 3 holding none) is re-checked once,
    so that halt is recorded here.
    """
    from opentine._cli_stop_run import exit_if_halted
    from opentine._stop_runner import HALT_EXIT

    signed = signed and code == HALT_EXIT  # a halted --model child signs, then exits 3
    if runner.supervised.reason is None and code != 0 and not signed:
        try:
            runner.guard.check()
        except Halt as halt:
            runner.supervised.halt(halt)
            runner.supervised.halted_ms = runner.supervised.clock_ms()
    exit_if_halted(runner.finish())
    raise SystemExit(code if code >= 0 else 128 - code)


__all__ = ["SUPERVISED_ENV", "child_argv", "finish", "marker", "supervise"]
