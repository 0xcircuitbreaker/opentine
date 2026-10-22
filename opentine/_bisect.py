"""``tine bisect``: find the first bad run in a sequence, or the first bad step.

Three kinds of sequence, all ordered good → bad:

* a fork lineage (default): from BAD back through ``forked_from`` to GOOD;
* an explicit run list (``--runs``), e.g. the same task on successive models;
* the steps of one run (``--steps RUN``): the evaluator decides, per step, whether
  the run had already gone wrong by that point.

The search is git's: keep the last known good and first known bad, test the
midpoint, repeat. Verdicts come from ``good``/``bad``/``skip`` or from
``bisect run`` (an evaluator command's exit code, as with ``git bisect run``:
0 good, 125 skip, 1-127 bad, 128+ abort; or a recorded evaluation score). The
state is one JSON file; a repository also records each verdict on the run as
an annotation (``bisect:good`` / ``bisect:bad`` tag plus metadata).
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

MAX_CANDIDATES = 10_000
MAX_LINEAGE = 1000
SKIP_EXIT = 125


class BisectError(ValueError):
    pass


@dataclass
class BisectState:
    mode: str  # "lineage", "runs" or "steps"
    candidates: list[str]
    good: int
    bad: int
    run: str = ""  # the run whose steps are bisected, in "steps" mode
    skipped: list[int] = field(default_factory=list)
    log: list[dict[str, Any]] = field(default_factory=list)
    version: int = 1

    @property
    def done(self) -> bool:
        return not self._open()

    def _open(self) -> list[int]:
        return [i for i in range(self.good + 1, self.bad) if i not in self.skipped]

    def current(self) -> int | None:
        """The candidate to test next: the open midpoint, or None once found."""
        remaining = self._open()
        if not remaining:
            return None
        middle = (self.good + self.bad) // 2
        return min(remaining, key=lambda index: (abs(index - middle), index))

    def first_bad(self) -> str | None:
        return self.candidates[self.bad] if self.done else None

    def mark(self, index: int, verdict: str) -> None:
        if not self.good < index < self.bad:
            raise BisectError("that item is outside the range still being searched")
        if verdict == "good":
            self.good = index
        elif verdict == "bad":
            self.bad = index
        elif verdict == "skip":
            self.skipped.append(index)
        else:
            raise BisectError(f"unknown verdict {verdict!r}")
        self.log.append({"item": self.candidates[index], "verdict": verdict, "at": time.time()})

    def index_of(self, item: str) -> int:
        matches = [i for i, name in enumerate(self.candidates) if name == item]
        if not matches:
            matches = [i for i, name in enumerate(self.candidates) if name.startswith(item)]
        if len(matches) != 1:
            raise BisectError(f"{item[:80]!r} names {len(matches)} items in this bisect")
        return matches[0]


def start(candidates: list[str], good: str, bad: str, *, mode: str, run: str = "") -> BisectState:
    if len(candidates) > MAX_CANDIDATES:
        raise BisectError("too many items to bisect")
    state = BisectState(mode=mode, candidates=list(candidates), good=0, bad=0, run=run)
    state.good, state.bad = state.index_of(good), state.index_of(bad)
    if state.good >= state.bad:
        raise BisectError("GOOD must come before BAD in the sequence")
    state.log.append({"item": candidates[state.bad], "verdict": "bad", "at": time.time()})
    state.log.append({"item": candidates[state.good], "verdict": "good", "at": time.time()})
    return state


def lineage(load_run: Any, bad: str, good: str) -> list[str]:
    """Run ids from GOOD to BAD following ``forked_from`` back from BAD."""
    chain, current = [], bad
    for _ in range(MAX_LINEAGE):
        run = load_run(current)
        chain.append(run.id)
        if good and (run.id.startswith(good) or current == good):
            return list(reversed(chain))
        parent = (run.metadata or {}).get("forked_from") if isinstance(run.metadata, dict) else None
        if not isinstance(parent, str) or not parent or parent in chain:
            break
        current = parent
    raise BisectError("GOOD is not an ancestor of BAD through forks; pass --runs instead")


def save(path: Path, state: BisectState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(asdict(state), sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def load(path: Path) -> BisectState:
    try:
        if path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
            raise BisectError("bisect state is not a regular file of sane size")
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BisectError("no bisect in progress; run `tine bisect start BAD GOOD`") from None
    except (OSError, ValueError) as exc:
        raise BisectError(f"bisect state is unreadable: {exc}") from None
    try:
        state = BisectState(**{key: data[key] for key in BisectState.__dataclass_fields__})
    except (KeyError, TypeError):
        raise BisectError("bisect state is malformed; run `tine bisect reset`") from None
    if not (
        isinstance(state.candidates, list)
        and all(isinstance(item, str) for item in state.candidates)
        and isinstance(state.good, int)
        and isinstance(state.bad, int)
        and 0 <= state.good < state.bad < len(state.candidates)
    ):
        raise BisectError("bisect state is malformed; run `tine bisect reset`")
    return state


def score_verdict(scores: dict[str, float], spec: str) -> str:
    """``good`` or ``bad`` for a recorded score against ``NAME>=X`` (or > <= < ==)."""
    for op in (">=", "<=", "==", ">", "<"):
        if op in spec:
            name, _, threshold = spec.partition(op)
            break
    else:
        raise BisectError("--score takes NAME>=X (or >, <=, <, ==)")
    name = name.strip()
    try:
        limit = float(threshold)
    except ValueError:
        raise BisectError(f"--score threshold {threshold!r} is not a number") from None
    if name not in scores:
        return "skip"
    value = scores[name]
    passed = {
        ">=": value >= limit,
        "<=": value <= limit,
        "==": value == limit,
        ">": value > limit,
        "<": value < limit,
    }[op]
    return "good" if passed else "bad"


def exit_verdict(code: int) -> str:
    if code == 0:
        return "good"
    if code == SKIP_EXIT:
        return "skip"
    if 0 < code < 128:
        return "bad"
    raise BisectError(f"the evaluator exited {code}; bisect run stopped")


__all__ = [
    "BisectError",
    "BisectState",
    "exit_verdict",
    "lineage",
    "load",
    "save",
    "score_verdict",
    "start",
]
