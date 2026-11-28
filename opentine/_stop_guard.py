"""Check-before-act under a stop policy: a fresh signed continue proof, or halt.

:class:`StopGuard` answers one question before each step of a run: may run RUN
of fleet FLEET act now? It reads the stop channel (:mod:`opentine._stop_channel`)
and raises :class:`Halt` (fail closed) when

* the channel cannot be read or does not verify under the pinned key
  (``stop.channel-unreachable``), or shrank or forked since the last read
  (``stop.channel-rollback``);
* it holds any stop entry, verified or not (``stop.stopped``; the log is the
  fleet's own);
* no valid continue proof names this fleet and run (``stop.no-continue``), the
  newest one has a lower ``seq`` than one accepted before
  (``stop.continue-rollback``), is bound to another channel key or to a
  checkpoint this log does not extend (``stop.continue-unbound``), is dated in
  the future beyond the allowed skew (``stop.continue-future``), or is older
  than the freshness window (``stop.continue-stale``).

Once halted a guard stays halted. The clock is injected (``clock_ms``); nothing
here sleeps. :class:`Watchdog` re-runs the check while a long step is in
flight and calls back once on the first halt.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine import _stop_channel, _stop_proof


class Halt(RuntimeError):
    """A run must stop now; ``code`` is a ``stop.*`` reason, ``stop`` the stop entry if any."""

    def __init__(self, code: str, message: str, stop: str | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.stop = code, message, stop


def anchored_clock(wall: Callable[[], float] = time.time,
                   mono: Callable[[], float] = time.monotonic) -> Callable[[], int]:  # fmt: skip
    """Milliseconds: the wall clock read once, then advanced only by the monotonic clock.

    Setting the system clock back while a run is in flight cannot keep a proof fresh.
    """
    start_wall, start_mono = wall(), mono()
    return lambda: int((start_wall + (mono() - start_mono)) * 1000)


_now_ms = anchored_clock()  # the process's clock (a test injects its own)


class StopGuard:
    def __init__(self, policy: dict[str, Any], store: Path | None, run: str, *,
                 base: Path | None = None,
                 clock_ms: Callable[[], int] | None = None) -> None:  # fmt: skip
        self.policy, self.store, self.run = policy, store, run
        self.clock_ms = clock_ms or (lambda: _now_ms())
        channel = Path(policy["channel"])
        self.channel = channel if channel.is_absolute() or base is None else base / channel
        self.halted: Halt | None = None
        self.accepted: dict[str, Any] | None = None
        self.checks = 0
        self._size, self._root, self._seq, self._last_ms = 0, None, 0, 0
        self._lock = threading.Lock()

    def now_ms(self) -> int:
        """The clock, never earlier than any time this guard has already read."""
        self._last_ms = max(self._last_ms, int(self.clock_ms()))
        return self._last_ms

    @property
    def window_ms(self) -> int:
        return int(self.policy["window_s"]) * 1000

    def check(self) -> dict[str, Any]:
        """The accepted continue proof's summary, or raise :class:`Halt`."""
        with self._lock:
            self.checks += 1
            if self.halted is not None:
                raise self.halted
            try:
                found = self._check()
            except Halt as halt:
                self.halted = halt
                raise
            self.accepted = found
            return found

    def _snapshot(self) -> _stop_channel.Snapshot:
        fleet, vkey = self.policy["fleet"], self.policy["vkey"]
        try:
            snap = _stop_channel.snapshot(self.channel, fleet, vkey)
        except (_stop_channel.ChannelError, ValueError) as exc:
            raise Halt("stop.channel-unreachable", str(exc)) from None
        if snap.size < self._size or (self._root is not None
                                      and snap.prefix_root(self._size) != self._root):  # fmt: skip
            raise Halt("stop.channel-rollback", f"the stop channel went from {self._size} "
                       f"entries to {snap.size} or no longer extends what was read")  # fmt: skip
        self._size, self._root = snap.size, snap.root
        return snap

    def _check(self) -> dict[str, Any]:
        snap = self._snapshot()
        fleet = self.policy["fleet"]
        for entry in snap.entries:
            claim = entry["payload"].get("claim")
            if entry["kind"] == "stop":  # this fleet's own log: any stop entry halts
                claim = claim if isinstance(claim, dict) else {}
                reason = str(claim.get("reason") or "")[:200]
                raise Halt("stop.stopped", f"fleet {fleet} was stopped: {reason}",
                           entry["attestation"])  # fmt: skip
        keys, refusal = _stop_proof.authorities(self.store)
        best: tuple[int, dict[str, Any], str] | None = None
        for entry in snap.entries:
            payload = entry["payload"]
            claim = payload.get("claim")
            if (entry["kind"] != "continue" or not isinstance(claim, dict)
                    or claim.get("fleet") != fleet or claim.get("run") != self.run):  # fmt: skip
                continue
            if not _stop_proof.well_formed_continue(claim):
                continue
            if _stop_proof.check(payload, _stop_proof.CONTINUE, keys, refusal) is not None:
                continue
            if best is None or claim["seq"] > best[0]:
                best = (claim["seq"], claim, entry["attestation"])
        if best is None:
            raise Halt("stop.no-continue", f"no valid continue proof for run {self.run} of "
                       f"fleet {fleet} ({refusal if not keys else 'none signed'})")  # fmt: skip
        seq, claim, oid = best
        if seq < self._seq:
            raise Halt("stop.continue-rollback", f"continue seq {seq} after {self._seq}")
        self._bound(snap, claim)
        now = self.now_ms()
        issued = _stop_proof.parse_at(claim["issued_at"])
        if issued is None or issued > now + int(self.policy["skew_s"]) * 1000:
            raise Halt("stop.continue-future", f"continue proof {oid} is dated in the future")
        window = min(self.window_ms, claim["window_s"] * 1000)
        if now - issued > window:
            age = (now - issued) // 1000
            raise Halt("stop.continue-stale", f"the newest continue proof ({oid}, seq {seq}) "
                       f"is {age} s old; the window is {window // 1000} s")  # fmt: skip
        self._seq = seq
        return {"proof": oid, "seq": seq, "issued_at": claim["issued_at"], "age_ms": now - issued,
                "window_s": window // 1000, "checkpoint": snap.checkpoint()}  # fmt: skip

    def _bound(self, snap: _stop_channel.Snapshot, claim: dict[str, Any]) -> None:
        point = claim["checkpoint"]
        if claim["channel"] != self.policy["vkey"] or point["origin"] != snap.origin:
            raise Halt("stop.continue-unbound", "the continue proof is bound to another channel")
        try:
            extends = snap.prefix_root(point["size"]) == point["root"]
        except _stop_channel.ChannelError:
            extends = False
        if not extends:
            raise Halt(
                "stop.continue-unbound",
                "the continue proof names a checkpoint this log does not extend",
            )


class Watchdog:
    """Re-check *guard* every *interval_s* until *done* is set; call *on_halt* once."""

    def __init__(self, guard: StopGuard, on_halt: Callable[[Halt], None], interval_s: float,
                 done: threading.Event | None = None) -> None:  # fmt: skip
        self.guard, self.on_halt, self.interval_s = guard, on_halt, interval_s
        self.done = done or threading.Event()
        self.fired = threading.Event()
        self._thread: threading.Thread | None = None

    def tick(self) -> bool:
        """One check; ``True`` when it halted (and *on_halt* ran)."""
        if self.fired.is_set():
            return True
        try:
            self.guard.check()
        except Halt as halt:
            self.fired.set()
            self.on_halt(halt)
            return True
        return False

    def _loop(self) -> None:
        while not self.done.wait(self.interval_s):
            if self.tick():
                return

    def start(self) -> Watchdog:
        self._thread = threading.Thread(target=self._loop, daemon=True, name="tine-stop-watchdog")
        self._thread.start()
        return self

    def stop(self) -> None:
        self.done.set()
        if self._thread is not None:
            self._thread.join()


__all__ = ["Halt", "StopGuard", "Watchdog", "anchored_clock"]
