"""Seeded interleavings of two or more threads, one shared call at a time.

Each worker calls ``Lockstep.point()`` before every shared operation (a wrapped
client does it for every method). The controller lets exactly one waiting
worker run to its next point, picked by a seeded ``random.Random``, so a seed
names one interleaving and a failure replays exactly. No sleeps, no timing.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from typing import Any


class Lockstep:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.cv = threading.Condition()
        self.waiting: set[str] = set()
        self.done: set[str] = set()
        self.turn: str | None = None
        self.names: set[str] = set()
        self.errors: dict[str, BaseException] = {}
        self.steps = 0

    def point(self) -> None:
        name = threading.current_thread().name
        if name not in self.names:
            return  # setup and checks run free
        with self.cv:
            self.waiting.add(name)
            self.cv.notify_all()
            self.cv.wait_for(lambda: self.turn == name)
            self.turn = None
            self.waiting.discard(name)
            self.cv.notify_all()

    def run(self, jobs: dict[str, Callable[[], Any]], *, limit: int = 100_000) -> dict:
        results: dict[str, Any] = {}
        self.names = set(jobs)

        def body(name: str, job: Callable[[], Any]) -> None:
            try:
                self.point()  # start in step with the others
                results[name] = job()
            except BaseException as exc:  # noqa: BLE001 - reported to the test
                self.errors[name] = exc
            finally:
                with self.cv:
                    self.done.add(name)
                    self.cv.notify_all()

        threads = [threading.Thread(target=body, args=(n, j), name=n, daemon=True)
                   for n, j in jobs.items()]  # fmt: skip
        for thread in threads:
            thread.start()
        with self.cv:
            while True:
                self.cv.wait_for(lambda: self.turn is None
                                 and self.waiting | self.done == self.names)  # fmt: skip
                if self.done == self.names:
                    break
                self.steps += 1
                if self.steps > limit:
                    raise AssertionError("interleaving did not finish")
                self.turn = self.rng.choice(sorted(self.waiting))
                self.cv.notify_all()
        for thread in threads:
            thread.join()
        return results


class Stepped:
    """Wrap *inner* so every method call is one scheduling point."""

    def __init__(self, inner: Any, step: Lockstep):
        self._inner, self._step = inner, step

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if not callable(attr):
            return attr

        def call(*args: Any, **kwargs: Any) -> Any:
            self._step.point()
            return attr(*args, **kwargs)

        return call
