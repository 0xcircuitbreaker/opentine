"""The LLM-as-judge scorer: each judgement is recorded as its own run (0.45).

``llm-judge:PROVIDER[:MODEL]`` asks the model to grade one output against the
item and its rubric. The prompt and the model's reply are saved as a run in
the runs directory (tagged ``eval-judge``) before the verdict is signed, and
the verdict's ``judge_run`` names that run, so the judgement can be replayed
and audited like any other run. The model must answer with a line
``SCORE: <0..1>``. From 0.89 a reply without one, or with a score outside
0..1, is an error (the item is errored, never scored 0); the judge run is
still saved first.

0.65: the scorer's version is the pin of its judge provenance (model, prompt
digest, rubric digest, sampling parameters; :mod:`opentine._judge_provenance`),
so the signed verdict carries it. A rubric is appended to the prompt.

Tests swap :func:`_model` for a fake adapter; nothing here opens a socket by
itself.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

from opentine._eval_scorers import Scorer

DEFAULT_PROMPT = (
    "You are grading an AI system's answer.\n"
    "Question: {input}\nReference answer: {expected}\nAnswer to grade: {output}\n\n"
    "Reply with a short reason, then a final line 'SCORE: <number from 0 to 1>'."
)
SCORE_LINE = re.compile(r"SCORE:\s*([01](?:\.[0-9]+)?)\b", re.IGNORECASE)


def _model(spec: str, api_key: str | None = None) -> Any:
    from opentine.models import model_class, resolve_model

    if api_key is None:
        return resolve_model(spec)
    provider, _, model = spec.partition(":")
    adapter = model_class(provider)
    return adapter(model, api_key=api_key) if model else adapter(api_key=api_key)


def _reply_text(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        for key in ("text", "content", "output"):
            value = response.get(key)
            if isinstance(value, str):
                return value
            if isinstance(value, list):
                return "".join(str(b.get("text", "")) for b in value if isinstance(b, dict))
    return ""


def _show(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


class JudgeParseError(ValueError):
    """A judge reply with no usable score: an error, never a silent 0."""


def judge_score(text: str) -> float:
    found = SCORE_LINE.findall(text)
    if not found:
        raise JudgeParseError("the judge reply has no 'SCORE: <0..1>' line")
    if len(set(found)) > 1:
        raise JudgeParseError(f"the judge reply gives more than one score: {sorted(set(found))}")
    score = float(found[-1])
    if not 0.0 <= score <= 1.0:
        raise JudgeParseError(f"the judge score {score} is outside 0..1")
    return score


def judge_scorer(spec: str, *, prompt: str | None = None, runs_dir: Path | None = None,
                 api_key: str | None = None, rubric: str | None = None) -> Scorer:  # fmt: skip
    """The ``llm-judge`` scorer for *spec*; judge runs go to *runs_dir*.

    *api_key* is the model credential (the review runner passes the one its
    ``runner.toml`` names, as it does for reviewers); each call's cost is
    recorded on its judge run and appended to the scorer's ``spent``.
    """
    from opentine import _judge_provenance
    from opentine._cli_common import _runs_dir
    from opentine.graph import Run, RunStatus, StepKind

    template = prompt or DEFAULT_PROMPT
    provenance = _judge_provenance.build(spec, template, rubric=rubric, sampling={"temperature": 0})
    version = _judge_provenance.pin(provenance)
    model = _model(spec) if api_key is None else _model(spec, api_key)
    spent: list[float] = []
    target = Path(runs_dir) if runs_dir is not None else _runs_dir()

    def score(item: dict[str, Any], output: Any) -> tuple[float, str]:
        text = template.format(
            input=_show(item.get("input")),
            expected=_show(item.get("expected", "")),
            output=_show(output),
        )
        if rubric is not None:
            text += "\n\nRubric:\n" + rubric
        messages = [{"role": "user", "content": text}]
        response = asyncio.run(model.complete(messages, temperature=0.0))
        reply = _reply_text(response)
        meta = response if isinstance(response, dict) else {}
        try:
            value: float | None = judge_score(reply)
        except JudgeParseError as exc:
            value, problem = None, exc
        run = Run(
            model_info=spec,
            user_prompt=text,
            tags=["eval-judge"],
            metadata={
                "eval_judge": {
                    "item": item.get("id"),
                    "scorer_version": version,
                    "provenance": provenance,
                }
            },
        )
        usage = meta.get("usage") if isinstance(meta.get("usage"), dict) else None
        billing = meta.get("billing") if isinstance(meta.get("billing"), dict) else None
        cost = meta.get("cost") if isinstance(meta.get("cost"), (int, float)) else 0.0
        run.add_step(StepKind.model, {"messages": messages}, {"text": reply}, model_info=spec,
                     cost=float(cost), usage=usage, billing=billing)  # fmt: skip
        spent.append(run.total_cost)
        run.status = RunStatus.completed
        target.mkdir(parents=True, exist_ok=True)
        run.save(target / f"{run.id}.tine")
        if value is None:
            raise JudgeParseError(f"{problem} (judge run {run.id})")
        return value, run.id

    return Scorer("llm-judge", version, score, {"model": spec, "provenance": provenance}, spent)


__all__ = ["DEFAULT_PROMPT", "JudgeParseError", "judge_score", "judge_scorer"]
