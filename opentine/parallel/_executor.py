"""The bounded concurrent executor behind ``tine fan-out`` and ``tine run --parallel``.

* At most ``jobs`` members run at once: ``jobs`` worker threads each run one
  member to completion (its whole process tree reaped) before taking the next.
* Every member starts in its own process group (POSIX, under the Linux
  subreaper) or suspended inside a kill-on-close Job Object (Windows), through
  the same launch path as the shell tool (:mod:`opentine.tools._process`), and is
  killed *with its descendants* on timeout, on budget exhaustion, on stop, and
  after a normal exit too (a member may leave background children behind).
* The :class:`~opentine.budget.SharedLedger` is consulted before every start and
  polled while members run; members report cumulative cost by writing a number
  to ``$OPENTINE_FANOUT_COST_FILE`` (``tine run`` does this itself).
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from opentine.budget import SharedLedger
from opentine.tools import _subreaper
from opentine.tools._batch_guard import refuse_batch_injection
from opentine.tools._process import _attach_kill_job, _cleanup_owned, _group_flags

#: Final statuses. ``ok``/``failed`` are finished; the rest are rerun by ``--resume``.
FINISHED = frozenset({"ok", "failed"})
STATUSES = FINISHED | {"pending", "timeout", "budget", "stopped", "skipped", "error"}
MAX_COST_FILE = 64


@dataclass
class Member:
    key: str  # stable id within the fan-out ("0", "1", ...)
    argv: list[str]
    env: dict[str, str]
    cwd: str | None = None
    cost_file: Path | None = None
    log: Path | None = None
    info: dict = field(default_factory=dict)  # echoed in status events


@dataclass
class Outcome:
    key: str
    status: str
    returncode: int | None = None
    cost: str | None = None
    seconds: float = 0.0
    detail: str = ""


#: What a member may report as its cost: a decimal number, nothing else.
_NUMBER = re.compile(r"[0-9.eE+-]{1,64}")


def read_cost(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_COST_FILE + 1)
    except OSError:
        return None
    if not raw.strip():
        return None
    text = raw.decode("ascii", "replace").strip() if len(raw) <= MAX_COST_FILE else ""
    return text if _NUMBER.fullmatch(text) else "NaN"  # a number, never terminal text


class Executor:
    def __init__(
        self,
        members: list[Member],
        *,
        jobs: int,
        timeout: float | None = None,
        ledger: SharedLedger | None = None,
        on_event: Callable[[dict], None] | None = None,
        poll: float = 0.05,
    ):
        if type(jobs) is not int or jobs < 1:
            raise ValueError("--jobs must be a positive integer")
        if timeout is not None and not timeout > 0:
            raise ValueError("--timeout must be positive")
        self.members = list(members)
        self.jobs = min(jobs, max(1, len(self.members)))
        self.timeout = timeout
        self.ledger = ledger or SharedLedger()
        self._emit = on_event or (lambda event: None)
        self._poll = poll
        self._lock = threading.Lock()
        self._queue = list(reversed(self.members))
        self._stop = threading.Event()
        self.outcomes: dict[str, Outcome] = {}
        self.active = 0
        self.peak = 0

    def stop(self) -> None:
        """Kill every running member's tree and start nothing more."""
        self._stop.set()

    def _event(self, event: dict) -> None:
        with self._lock:
            self._emit(event)

    def _next(self) -> Member | None:
        with self._lock:
            if not self._queue:
                return None
            if self._stop.is_set() or not self.ledger.admit():
                # Fail closed: nothing queued starts once stopped or out of budget.
                reason = "stopped" if self._stop.is_set() else "budget"
                while self._queue:
                    member = self._queue.pop()
                    self.outcomes[member.key] = Outcome(member.key, "skipped", detail=reason)
                    self._emit({"event": "skipped", "member": member.key, "reason": reason})
                return None
            self.active += 1
            self.peak = max(self.peak, self.active)
            return self._queue.pop()

    def _worker(self) -> None:
        while (member := self._next()) is not None:
            try:
                outcome = self._run(member)
            except Exception as exc:  # a launch failure is that member's error only
                outcome = Outcome(member.key, "error", detail=type(exc).__name__)
            with self._lock:
                self.active -= 1
                self.outcomes[member.key] = outcome
                self._emit(
                    {
                        "event": "exit",
                        "member": member.key,
                        "status": outcome.status,
                        "returncode": outcome.returncode,
                        "cost": outcome.cost,
                        "seconds": round(outcome.seconds, 3),
                        **member.info,
                    }
                )

    def _launch(self, member: Member) -> tuple[subprocess.Popen[bytes], object]:
        refuse_batch_injection(member.argv)
        if member.cost_file is not None:
            member.cost_file.unlink(missing_ok=True)  # a resumed member starts at zero
        out = open(member.log, "ab") if member.log else subprocess.DEVNULL  # noqa: SIM115
        try:
            launch = subprocess.Popen if os.name == "nt" else _subreaper.popen
            process = launch(
                member.argv,
                cwd=member.cwd,
                env=member.env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
                **_group_flags(),
            )
        finally:
            if out is not subprocess.DEVNULL:
                out.close()
        return process, _attach_kill_job(process)

    def _run(self, member: Member) -> Outcome:
        started = time.monotonic()
        process, job = self._launch(member)
        self._event({"event": "start", "member": member.key, "pid": process.pid, **member.info})
        status, returncode = "", None
        try:
            while True:
                try:
                    returncode = process.wait(timeout=self._poll)
                    break
                except subprocess.TimeoutExpired:
                    pass
                cost = read_cost(member.cost_file)
                if cost is not None:
                    self.ledger.report(member.key, cost)
                if self._stop.is_set():
                    status = "stopped"
                elif self.ledger.closed:
                    status = "budget"
                elif self.timeout is not None and time.monotonic() - started > self.timeout:
                    status = "timeout"
                if status:
                    break
        finally:
            # Always, even after a clean exit: the member owns a fresh group/job,
            # and anything it left running in there dies with it.
            _cleanup_owned(process, job)
            if returncode is None:
                try:
                    returncode = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    returncode = None
        cost = read_cost(member.cost_file)
        if cost is not None:
            self.ledger.report(member.key, cost)
        elif not status:
            self.ledger.unknown(member.key)
        status = status or ("ok" if returncode == 0 else "failed")
        return Outcome(member.key, status, returncode, cost, time.monotonic() - started)

    def run(self) -> dict[str, Outcome]:
        threads = [
            threading.Thread(target=self._worker, name=f"tine-member-{index}", daemon=True)
            for index in range(self.jobs)
        ]
        for thread in threads:
            thread.start()
        try:
            for thread in threads:
                while thread.is_alive():
                    thread.join(timeout=0.2)  # stays interruptible by Ctrl-C
        except BaseException:
            self.stop()
            for thread in threads:
                thread.join()
            raise
        return self.outcomes


__all__ = ["FINISHED", "STATUSES", "Executor", "Member", "Outcome", "read_cost"]
