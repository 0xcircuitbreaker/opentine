"""Label judges (0.89): a label, a probability and an explicit abstain.

A label judge asks a model to put one item in one of a fixed set of labels. The
reply must end with::

    LABEL: <one of the allowed labels>
    PROBABILITY: <0..1>          (optional: the judge's confidence in that label)

or with ``LABEL: ABSTAIN`` (or a line ``ABSTAIN``) when the judge declines. The
parsed outcome is always one of three statuses:

``label``    a single allowed label (and a probability when one was given);
``abstain``  the judge said so explicitly;
``error``    anything else: no label line, a label outside the set, two
             different labels, a probability outside 0..1.

An abstain or an error is never a score of 0, and an error is never a label: the
caller counts it as not scored. The same rule applies to the numeric
``llm-judge`` scorer, whose reply without a ``SCORE:`` line is now an error
(:mod:`opentine._eval_judge`).

Each judgement is saved as its own run (tagged ``eval-judge``) with its judge
provenance (:mod:`opentine._judge_provenance`), exactly as the numeric judge
does. Tests swap :func:`opentine._eval_judge._model` for a fake adapter.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

ABSTAIN = "ABSTAIN"
STATUSES = ("label", "abstain", "error")
LABEL_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_LABEL_LINE = re.compile(r"^\s*LABEL:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_PROB_LINE = re.compile(r"^\s*PROBABILITY:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_ABSTAIN_LINE = re.compile(r"^\s*ABSTAIN\s*$", re.IGNORECASE | re.MULTILINE)
MAX_REPLY = 1 << 20

DEFAULT_PROMPT = (
    "You are labelling an AI system's answer.\n"
    "Question: {input}\nReference answer: {expected}\nAnswer to label: {output}\n\n"
    "Allowed labels: {labels}.\n"
    "Reply with a short reason, then a line 'LABEL: <label>' and a line "
    "'PROBABILITY: <number from 0 to 1>'. If you cannot decide, reply 'LABEL: ABSTAIN'."
)


def check_labels(labels: list[str]) -> list[str]:
    """The allowed labels, checked: 2..64 distinct names, none of them ABSTAIN."""
    out = [str(x) for x in labels]
    if not 2 <= len(out) <= 64 or len(set(out)) != len(out):
        raise ValueError("a label judge needs 2 to 64 distinct labels")
    if any(not LABEL_RE.fullmatch(x) or x.upper() == ABSTAIN for x in out):
        raise ValueError("labels are 1-64 of A-Z a-z 0-9 _ . - and none is ABSTAIN")
    return out


def _probability(text: str) -> str | None:
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise ValueError(f"probability {text!r} is not a number") from None
    if not value.is_finite() or not 0 <= value <= 1:
        raise ValueError(f"probability {text!r} is outside 0..1")
    return format(value.normalize(), "f")


def parse(reply: str, labels: list[str]) -> dict[str, Any]:
    """``{"status", "label", "probability", "reason"}`` for one judge reply."""
    if not isinstance(reply, str) or len(reply) > MAX_REPLY:
        return _out("error", reason="the reply is not text or is too long")
    found = [m.group(1) for m in _LABEL_LINE.finditer(reply)]
    abstained = bool(_ABSTAIN_LINE.search(reply)) or any(f.upper() == ABSTAIN for f in found)
    named = sorted({f for f in found if f.upper() != ABSTAIN})
    if abstained and not named:
        return _out("abstain", reason="the judge abstained")
    if abstained or len(named) > 1:
        return _out("error", reason=f"the reply names more than one outcome: {named}")
    if not named:
        return _out("error", reason="the reply has no LABEL line")
    if named[0] not in labels:
        return _out("error", reason=f"label {named[0]!r} is not one of {labels}")
    probs = [m.group(1) for m in _PROB_LINE.finditer(reply)]
    if len(set(probs)) > 1:
        return _out("error", reason="the reply gives more than one probability")
    try:
        prob = _probability(probs[0]) if probs else None
    except ValueError as exc:
        return _out("error", reason=str(exc))
    return _out("label", label=named[0], probability=prob)


def _out(status: str, *, label: str | None = None, probability: str | None = None,
         reason: str = "") -> dict[str, Any]:  # fmt: skip
    return {"status": status, "label": label, "probability": probability, "reason": reason}


def label_judge(spec: str, labels: list[str], *, prompt: str | None = None,
                rubric: str | None = None, runs_dir: Path | None = None) -> Any:  # fmt: skip
    """A callable ``(item, output) -> outcome`` with ``.provenance`` and ``.version``."""
    import asyncio

    from opentine import _eval_judge, _judge_provenance
    from opentine._cli_common import _runs_dir
    from opentine.graph import Run, RunStatus, StepKind

    allowed = check_labels(labels)
    template = prompt or DEFAULT_PROMPT
    provenance = _judge_provenance.build(spec, template, rubric=rubric, sampling={"temperature": 0})
    version = _judge_provenance.pin(provenance)
    model = _eval_judge._model(spec)
    target = Path(runs_dir) if runs_dir is not None else _runs_dir()

    def judge(item: dict[str, Any], output: Any) -> dict[str, Any]:
        show = _eval_judge._show
        text = template.replace("{labels}", ", ".join(allowed)).format(
            input=show(item.get("input")), expected=show(item.get("expected", "")),
            output=show(output))  # fmt: skip
        if rubric is not None:
            text += "\n\nRubric:\n" + rubric
        messages = [{"role": "user", "content": text}]
        try:
            reply = _eval_judge._reply_text(asyncio.run(model.complete(messages, temperature=0.0)))
        except Exception as exc:  # noqa: BLE001 - a failed call is an error, never a label
            reply, outcome = "", _out("error", reason=f"the judge call failed: {exc}")
        else:
            outcome = parse(reply, allowed)
        meta = {"item": item.get("id"), "scorer_version": version, "provenance": provenance,
                "outcome": outcome}  # fmt: skip
        run = Run(model_info=spec, user_prompt=text, tags=["eval-judge"],
                  metadata={"eval_judge": meta})  # fmt: skip
        run.add_step(StepKind.model, {"messages": messages}, {"text": reply}, model_info=spec)
        run.status = RunStatus.completed
        target.mkdir(parents=True, exist_ok=True)
        run.save(target / f"{run.id}.tine")
        return {**outcome, "judge_run": run.id}

    judge.provenance = provenance  # type: ignore[attr-defined]
    judge.version = version  # type: ignore[attr-defined]
    judge.prompt = template  # type: ignore[attr-defined]
    return judge


__all__ = ["ABSTAIN", "DEFAULT_PROMPT", "STATUSES", "check_labels", "label_judge", "parse"]
