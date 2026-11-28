"""Running a child under a stop policy: one killable tree, halted on the first failed check.

:class:`Supervised` starts the command the way :mod:`opentine.tools._process`
does (its own process group and, on Linux, the subreaper supervisor; on Windows
a kill-on-close job object), so every sub-agent and child it spawns inherits
the stop: :meth:`Supervised.halt` kills the whole tree. A :class:`Watchdog`
re-checks the guard while the child runs, so a long step with no model call
still halts within one watchdog interval of the proof going stale.

After the child is gone :meth:`Supervised.measure` reports the time to halt
and the processes of the tree still alive (``residual_processes``: on Linux the
non-zombie processes still carrying the tree's scope marker or process group,
elsewhere whether the group still answers; on Windows the job object leaves
none), which :mod:`opentine._stop_compliance` signs.
"""

from __future__ import annotations

import os
import subprocess
import threading
from collections.abc import Callable
from typing import Any

from opentine._stop_guard import Halt, StopGuard, Watchdog


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except (OSError, IndexError):
        return False


def _pgrp(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat") as handle:
            return int(handle.read().rsplit(")", 1)[1].split()[2])
    except (OSError, IndexError, ValueError):
        return None


def residual(group: int, token: str | None) -> tuple[int, str]:
    """``(live processes of the tree, method)`` after a halt."""
    if os.name == "nt":
        return 0, "job-object"
    if os.path.isdir("/proc/self"):
        from opentine.tools._subreaper_sweep import SCOPE_ENV, _environ, _pids

        needle = f"{SCOPE_ENV}={token}".encode() if token else None
        me, count = os.getpid(), 0
        for pid in _pids():
            if pid == me or not _alive(pid):
                continue
            environ = _environ(pid) if needle else None
            if _pgrp(pid) == group or (environ and needle in environ.split(b"\0")):
                count += 1
        return count, "proc"
    try:
        os.killpg(group, 0)
    except OSError:
        return 0, "killpg"
    return 1, "killpg"


class Supervised:
    def __init__(self, guard: StopGuard, *, clock_ms: Callable[[], int] | None = None) -> None:
        self.guard, self.clock_ms = guard, clock_ms or guard.now_ms
        self.process: subprocess.Popen[bytes] | None = None
        self.job: Any = None
        self.token: str | None = None
        self.reason: Halt | None = None
        self.requested_ms: int | None = None
        self.halted_ms: int | None = None
        self.forwarded_after = 0
        self.refused_after = 0
        self._lock = threading.Lock()
        self.settle: Callable[[], Any] = lambda: threading.Event().wait(0.02)

    def launch(self, argv: list[str], env: dict[str, str], **popen: Any) -> subprocess.Popen[bytes]:
        from opentine.tools import _subreaper
        from opentine.tools._process import _attach_kill_job, _group_flags

        launch = subprocess.Popen if os.name == "nt" else _subreaper.popen
        self.process = launch(argv, env=env, **popen, **_group_flags())
        self.job = _attach_kill_job(self.process)
        state = getattr(self.process, "opentine_supervised", None)
        self.token = getattr(state, "token", None)
        return self.process

    def halt(self, reason: Halt) -> None:
        """Record why and when, then kill the whole tree (idempotent)."""
        with self._lock:
            if self.reason is not None:
                return
            self.reason, self.requested_ms = reason, self.clock_ms()
        if self.process is not None:
            from opentine.tools._process import _cleanup_owned

            _cleanup_owned(self.process, self.job)

    def admit(self) -> Halt | None:
        """Check before one action of the child; ``None`` to let it through."""
        try:
            self.guard.check()
        except Halt as halt:
            self.halt(halt)
            self.refused_after += 1
            return halt
        if self.reason is not None:
            self.refused_after += 1
            return self.reason
        return None

    def note_forwarded(self) -> None:
        if self.reason is not None:
            self.forwarded_after += 1

    def run(self, argv: list[str], env: dict[str, str], *, interval_s: float) -> int:
        """Launch, watch and wait; the child's exit code."""
        process = self.launch(argv, env)
        watchdog = Watchdog(self.guard, self.halt, interval_s).start()
        try:
            code = process.wait()
        finally:
            watchdog.stop()
        if self.reason is not None:
            self.halted_ms = self.clock_ms()
        else:
            from opentine.tools._process import _cleanup_owned

            _cleanup_owned(process, self.job)  # what the child left behind goes with it
        return code

    def measure(self) -> dict[str, Any]:
        """The halt's time and residue (call after :meth:`run`)."""
        assert self.reason is not None
        if self.process is None:  # an in-process run: nothing was spawned to outlive it
            count, method = 0, "in-process"
        else:
            count, method = residual(self.process.pid, self.token)
        for _ in range(100 if count else 0):  # SIGKILL lands asynchronously: wait, never
            self.settle()  # kill again first, which would hide a survivor
            count, method = residual(self.process.pid, self.token)
        if self.process is not None:
            from opentine.tools._process import _cleanup_owned

            _cleanup_owned(self.process, self.job)  # a survivor is counted, then still killed
        halted = self.halted_ms if self.halted_ms is not None else self.clock_ms()
        return {"code": self.reason.code, "message": self.reason.message,
                "stop": self.reason.stop, "requested_ms": self.requested_ms,
                "halted_ms": halted, "residual_processes": count, "residual_method": method,
                "forwarded_after_stop": self.forwarded_after,
                "refused_after_stop": self.refused_after}  # fmt: skip


__all__ = ["Supervised", "residual"]
