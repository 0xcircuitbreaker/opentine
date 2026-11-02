"""Replay fidelity labels: how faithfully each replayed step was reproduced.

A green ``tine replay --verify`` used to say *that* a replay matched, never
*what kind* of match it was. A cached replay proves the recording survives a
round trip byte for byte; a harness rerun proves the agent re-derived the same
step twice. Those are different claims, so every replayed step carries one
label from a fixed set, ordered strongest to weakest:

``exact``
    Served from the recording (cache mode): the step in the round-tripped
    artifact is field-for-field the recorded step, so its content digest (the
    step id) matches. Nothing was re-executed.
``recomputed-match``
    Re-executed (``--harness``): both reruns produced the same step at the same
    position, so the step's content digest is equal across executions.
``unavailable``
    Could not be reproduced: a step the replay should retain is missing from
    the artifact, or its recorded content carries a ``[REDACTED`` marker, so
    the original value is gone and no replay can stand behind it.
``diverged``
    The step is present but differs: a cached step that did not survive the
    round trip intact, or a rerun step the second execution did not reproduce.

There is no ``stubbed`` label: a cached replay answers *every* step from the
recording (that is ``exact``), and a harness rerun re-executes every step, so
the engine never observes a mix of re-run and answered-from-recording calls.

The run-level ``overall`` label is the weakest step's label (``None`` for a
replay with no steps). ``--min-fidelity LABEL`` fails verification when
``overall`` is weaker than LABEL.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

LABELS: tuple[str, ...] = ("exact", "recomputed-match", "unavailable", "diverged")
_RANK = {label: rank for rank, label in enumerate(LABELS)}
_MARKER = "[REDACTED"


@dataclass
class Fidelity:
    """Per-step labels (in replay order) plus the run-level roll-up."""

    steps: list[tuple[str, str]] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        found = {label: 0 for label in LABELS}
        for _, label in self.steps:
            found[label] += 1
        return found

    @property
    def overall(self) -> str | None:
        if not self.steps:
            return None
        return max((label for _, label in self.steps), key=_RANK.__getitem__)

    def meets(self, minimum: str | None) -> bool:
        """Whether every step is at least as strong as *minimum* (None: no floor)."""
        overall = self.overall
        return minimum is None or overall is None or _RANK[overall] <= _RANK[minimum]

    def to_dict(self, minimum: str | None = None) -> dict[str, Any]:
        return {
            "overall": self.overall,
            "counts": self.counts,
            "steps": [{"id": step, "label": label} for step, label in self.steps],
            "min_fidelity": minimum,
            "meets_minimum": self.meets(minimum),
        }


def _content(step: Any) -> dict[str, Any]:
    """The recorded fields; ``v3_kind`` is folded into the effective kind because a
    loader may spell a legacy kind either way without changing the step."""
    fields = asdict(step)
    fields["v3_kind"] = step.v3_kind or step.kind.value
    return fields


def _redacted(step: Any) -> bool:
    content = json.dumps([step.inputs, step.outputs, step.error], default=str)
    return _MARKER in content


def classify_cache(source: Any, expected: set[str], replayed: Any) -> Fidelity:
    """Label each retained step of a cached replay against the recorded source."""
    labels: list[tuple[str, str]] = []
    for step in source.steps:
        if step.id not in expected:
            continue
        copy = replayed.graph.steps.get(step.id)
        if copy is None or _redacted(step):
            labels.append((step.id, "unavailable"))
        elif _content(copy) == _content(step):
            labels.append((step.id, "exact"))
        else:
            labels.append((step.id, "diverged"))
    return Fidelity(labels)


def classify_rerun(first: Any, second: Any) -> Fidelity:
    """Label each step of the first rerun by whether the second reproduced it."""
    others = [step.id for step in second.steps]
    labels: list[tuple[str, str]] = []
    for index, step in enumerate(first.steps):
        if _redacted(step):
            labels.append((step.id, "unavailable"))
        elif index < len(others) and others[index] == step.id:
            labels.append((step.id, "recomputed-match"))
        else:
            labels.append((step.id, "diverged"))
    # Steps only the second execution produced are divergence too.
    labels.extend((extra, "diverged") for extra in others[len(first.steps) :])
    return Fidelity(labels)


def render_lines(fidelity: Fidelity, short: Any) -> list[str]:
    """Plain-text lines: one per step, then the summary."""
    lines = [f"  {short(step)} {label}" for step, label in fidelity.steps]
    counts = ", ".join(f"{label}={n}" for label, n in fidelity.counts.items() if n)
    lines.append(f"fidelity: {fidelity.overall or 'n/a'} ({counts or 'no steps'})")
    return lines
