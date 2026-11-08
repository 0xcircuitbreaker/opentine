"""The LLM-as-judge scorer: each judgement is recorded as its own run (0.45).

``llm-judge:PROVIDER[:MODEL]`` asks the model to grade one output against the
item and its rubric. The prompt and the model's reply are saved as a run in
the runs directory (tagged ``eval-judge``) before the verdict is signed, and
the verdict's ``judge_run`` names that run, so the judgement can be replayed
and audited like any other run. The model must answer with a line
``SCORE: <0..1>``; a reply without one scores 0.

Tests swap :func:`_model` for a fake adapter; nothing here opens a socket by
itself.
"""

from __future__ import annotations

import asyncio
import hashlib
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


def _model(spec: str) -> Any:
    from opentine.models import resolve_model

    return resolve_model(spec)


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


def judge_score(text: str) -> float:
    found = SCORE_LINE.findall(text)
    score = float(found[-1]) if found else 0.0
    return score if 0.0 <= score <= 1.0 else 0.0


def judge_scorer(spec: str, *, prompt: str | None = None, runs_dir: Path | None = None) -> Scorer:
    """The ``llm-judge`` scorer for *spec*; judge runs go to *runs_dir*."""
    from opentine._cli_common import _runs_dir
    from opentine.graph import Run, RunStatus, StepKind

    template = prompt or DEFAULT_PROMPT
    version = "1+sha256:" + hashlib.sha256(f"{spec}\0{template}".encode()).hexdigest()[:16]
    model = _model(spec)
    target = Path(runs_dir) if runs_dir is not None else _runs_dir()

    def score(item: dict[str, Any], output: Any) -> tuple[float, str]:
        text = template.format(
            input=_show(item.get("input")),
            expected=_show(item.get("expected", "")),
            output=_show(output),
        )
        messages = [{"role": "user", "content": text}]
        reply = _reply_text(asyncio.run(model.complete(messages, temperature=0.0)))
        value = judge_score(reply)
        run = Run(
            model_info=spec,
            user_prompt=text,
            tags=["eval-judge"],
            metadata={"eval_judge": {"item": item.get("id"), "scorer_version": version}},
        )
        run.add_step(StepKind.model, {"messages": messages}, {"text": reply}, model_info=spec)
        run.status = RunStatus.completed
        target.mkdir(parents=True, exist_ok=True)
        run.save(target / f"{run.id}.tine")
        return value, run.id

    return Scorer("llm-judge", version, score, {"model": spec})


__all__ = ["DEFAULT_PROMPT", "judge_score", "judge_scorer"]
