"""The stop policy as ``tine record`` and ``tine run`` apply it.

:func:`open_runner` finds the repository (``--repo``, else the current
directory) and its stop policy. With none, it returns ``None`` and the command
behaves exactly as before (D12). With one, the run must name its run id
(``--stop-run`` or ``$OPENTINE_STOP_RUN``; continue proofs are bound to it) and
a runner key (``--stop-key`` or ``$OPENTINE_STOP_KEY``; it signs the
compliance record); a missing one, or a policy that cannot be used, refuses the
command before anything starts (:class:`StopRefused`, fail closed). A run that
cannot obtain a fresh continue proof before it starts is refused the same way.

:class:`StopGate` puts the check in front of every model call the record proxy
forwards; the watchdog (:mod:`opentine._stop_supervise`) covers long steps.
After a halt :meth:`StopRunner.finish` signs and holds the compliance record.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._stop_guard import Halt, StopGuard
from opentine._stop_supervise import Supervised

HALT_EXIT = 3
RUN_ENV, KEY_ENV = "OPENTINE_STOP_RUN", "OPENTINE_STOP_KEY"


class StopRefused(RuntimeError):
    """The command may not start under the stop policy in force."""


class StopRunner:
    def __init__(self, repo: Any, policy: dict[str, Any], run: str, key: Any, *,
                 clock_ms: Callable[[], int] | None = None) -> None:  # fmt: skip
        self.repo, self.policy, self.run, self.key = repo, policy, run, key
        store = Path(repo.path)
        self.base = store.parent
        self.guard = StopGuard(policy, store, run, base=self.base, clock_ms=clock_ms)
        self.supervised = Supervised(self.guard, clock_ms=clock_ms)

    def preflight(self) -> dict[str, Any]:
        try:
            return self.guard.check()
        except Halt as halt:
            raise StopRefused(f"stop policy: {halt}") from None

    def check(self) -> None:
        """Check-before-act for an in-process step; raises :class:`Halt`."""
        halt = self.supervised.admit()
        if halt is not None:
            raise halt

    def finish(self) -> dict[str, Any] | None:
        """After a halt: the signed compliance record (``{"record", "claim"}``)."""
        from opentine import _stop_compliance

        if self.supervised.reason is None:
            return None
        measured = self.supervised.measure()
        issued = _stop_compliance.stop_time(self.policy, Path(self.repo.path), self.base,
                                            measured["stop"])  # fmt: skip
        claim = _stop_compliance.claim_for(self.policy, self.run, measured, issued)
        return {"record": _stop_compliance.record(self.repo, claim, self.key), "claim": claim}


class StopGate:
    """A record-proxy gate: the stop check first, then the budget gate if any."""

    def __init__(self, runner: StopRunner, inner: Any = None) -> None:
        self.runner, self.inner = runner, inner

    @property
    def denied(self) -> int:
        return getattr(self.inner, "denied", 0)

    def admit(self, *args: Any) -> dict[str, Any]:
        import json

        halt = self.runner.supervised.admit()
        if halt is not None:
            error = {"type": "opentine_stop", "code": halt.code, "message": halt.message}
            body = json.dumps({"error": error}, sort_keys=True).encode()
            return {"ok": False, "status": 503, "code": halt.code, "message": halt.message,
                    "body": body}  # fmt: skip
        self.runner.supervised.note_forwarded()
        if self.inner is not None:
            return self.inner.admit(*args)
        return {"ok": True, "ticket": None}

    def settle(self, ticket: Any, record: dict[str, Any]) -> None:
        if self.inner is not None:
            self.inner.settle(ticket, record)


def open_runner(where: str | None, run: str | None, key_path: str | None, *,
                clock_ms: Callable[[], int] | None = None) -> StopRunner | None:  # fmt: skip
    from opentine import _stop_policy

    repo = _stop_policy.discover(where)
    if repo is None:
        return None
    try:
        policy = _stop_policy.load(repo)
    except (ValueError, OSError) as exc:
        raise StopRefused(f"stop policy: {exc}") from None
    if policy is None:
        return None
    run = run or os.environ.get(RUN_ENV) or None
    key_path = key_path or os.environ.get(KEY_ENV) or None
    if not run:
        raise StopRefused(f"a stop policy is in force (fleet {policy['fleet']}): name this run "
                          f"with --stop-run ID or ${RUN_ENV}")  # fmt: skip
    if not key_path:
        raise StopRefused(f"a stop policy is in force: give the runner key with --stop-key KEY "
                          f"or ${KEY_ENV} (it signs the stop-compliance record)")  # fmt: skip
    from opentine._key_hygiene import ed25519_private

    try:
        key = ed25519_private(key_path)
    except (OSError, ValueError) as exc:
        raise StopRefused(f"stop key: {exc}") from None
    return StopRunner(repo, policy, run, key, clock_ms=clock_ms)


__all__ = ["HALT_EXIT", "KEY_ENV", "RUN_ENV", "StopGate", "StopRefused", "StopRunner",
           "open_runner"]  # fmt: skip
