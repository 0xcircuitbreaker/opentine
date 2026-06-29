"""Crash-safe streaming autosave for long runs.

The Autosaver writes *draft* checkpoints (atomic, marked ``draft: true``) at safe
boundaries during a run, then a clean *final* artifact via ``flush``. Throttling
uses AND-suppression — a write happens only when *every* configured gate has
elapsed — so the default of "checkpoint each step" can't degrade into an
O(n^2) save-on-every-step storm.
"""

from __future__ import annotations

import time
from pathlib import Path

from opentine.graph import Run, RunStatus

_TERMINAL = (RunStatus.completed, RunStatus.failed)


class Autosaver:
    def __init__(
        self,
        path: str | Path | None,
        *,
        every_n_steps: int = 0,
        every_seconds: float = 0.0,
    ):
        self.path = Path(path) if path else None
        self.every_n_steps = every_n_steps
        self.every_seconds = every_seconds
        self._last_step_count = 0
        self._last_time: float | None = None

    @property
    def enabled(self) -> bool:
        return self.path is not None and (self.every_n_steps > 0 or self.every_seconds > 0)

    def maybe_save(self, run: Run, *, force: bool = False) -> bool:
        """Write a draft checkpoint if both throttle gates have elapsed."""
        if not self.enabled:
            return False
        now = time.time()
        if self._last_time is None:
            self._last_time = now
        if not force:
            steps_since = len(run.steps) - self._last_step_count
            secs_since = now - self._last_time
            steps_ok = self.every_n_steps <= 0 or steps_since >= self.every_n_steps
            secs_ok = self.every_seconds <= 0 or secs_since >= self.every_seconds
            if not (steps_ok and secs_ok):
                return False
        run.save(self.path, draft=True)
        self._last_step_count = len(run.steps)
        self._last_time = now
        return True

    def flush(self, run: Run) -> Path | None:
        """Write the final artifact.

        A terminal (completed/failed) run is written clean (no draft marker, with
        fsync). A still-running run flushed on crash/exception stays marked draft
        so it is never mistaken for a finished, trustworthy artifact.
        """
        if self.path is None:
            return None
        final = run.status in _TERMINAL
        if final:
            run.metadata.pop("autosave", None)
        return run.save(self.path, draft=not final, fsync=final)
