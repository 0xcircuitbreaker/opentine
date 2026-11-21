"""Padding-resistant similarity for the oversight queue (0.76).

A whole-transcript cosine is diluted by text that has nothing to do with the
behaviour: a run that repeats a flagged run's tool steps but carries a long
benign prompt scores under the threshold. :func:`best` therefore also scores
overlapping word windows of the run in the same fitted space and keeps the
maximum, so the flagged steps are compared with the evidence on their own.

A window is as long as the evidence run (at least :data:`MIN_WINDOW_WORDS`
words; longer when the run would otherwise have over :data:`MAX_WINDOWS`
windows, so every word is still covered), and windows overlap by half, so
some window holds at least three quarters of any evidence-length stretch. A
run no longer than one window is scored whole only.

The remaining limit: text the run adds *inside* the copied steps (between
every flagged step) still dilutes each window, and a run whose total text
passes the search index's per-run budget is scored on the indexed part only
(docs/TRANSCRIPT_FLAGS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._transcript_space import Space, Sparse, dot

MIN_WINDOW_WORDS = 16
MAX_WINDOWS = 8192


def windows(text: str, width: int) -> list[str]:
    """Half-overlapping windows of about *width* words covering *text* (empty if short)."""
    words = text.split()
    width = max(MIN_WINDOW_WORDS, width)
    if len(words) <= width:
        return []
    size = max(width, -(-2 * len(words) // MAX_WINDOWS))
    step = max(1, size // 2)
    last = max(0, len(words) - size)
    starts = list(range(0, last, step)) + [last]
    return [" ".join(words[i : i + size]) for i in starts]


class Scorer:
    """Whole-run and best-window centred scores in one fitted :class:`Space`."""

    def __init__(self, space: Space, texts: dict[str, str]) -> None:
        self.space, self.texts = space, texts
        self._windows: dict[tuple[str, int], list[Sparse]] = {}

    def width(self, run: str) -> int:
        """The window width for evidence *run*: its own length in words."""
        return len(self.texts[run].split())

    def _vectors(self, run: str, width: int) -> list[Sparse]:
        key = (run, width)
        if key not in self._windows:
            self._windows[key] = [self.space.embed(w) for w in windows(self.texts[run], width)]
        return self._windows[key]

    def best(self, query: list[float], run: str, width: int) -> float:
        """The larger of the whole-run score and the best *width*-word window's score."""
        space = self.space
        score = space.score(query, run)
        qm = sum(q * m for q, m in zip(query, space.mean, strict=True))
        for vector in self._vectors(run, width):
            score = max(score, (dot(vector, query) - qm) / space._centred_norm(vector))
        return score


def scorer(texts: dict[str, str]) -> Any:
    return Scorer(Space(texts), texts)


__all__ = ["MAX_WINDOWS", "MIN_WINDOW_WORDS", "Scorer", "scorer", "windows"]
