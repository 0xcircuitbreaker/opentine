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


def judge_score(text: str) -> float:
    found = SCORE_LINE.findall(text)
    score = float(found[-1]) if found else 0.0
    return score if 0.0 <= score <= 1.0 else 0.0


def judge_scorer(spec: str, *, prompt: str | None = None, runs_dir: Path | None = None,
                 api_key: str | None = None) -> Scorer:  # fmt: skip
    """The ``llm-judge`` scorer for *spec*; judge runs go to *runs_dir*.

    *api_key* is the model credential (the review runner passes the one its
    ``runner.toml`` names, as it does for reviewers); each call's cost is
    recorded on its judge run and appended to the scorer's ``spent``.
    """
    from opentine._cli_common import _runs_dir
    from opentine.graph import Run, RunStatus, StepKind

    template = prompt or DEFAULT_PROMPT
    version = "1+sha256:" + hashlib.sha256(f"{spec}\0{template}".encode()).hexdigest()[:16]
    model = _model(spec) if api_key is None else _model(spec, api_key)
    spent: list[float] = []
    target = Path(runs_dir) if runs_dir is not None else _runs_dir()

    def score(item: dict[str, Any], output: Any) -> tuple[float, str]:
        text = template.format(
            input=_show(item.get("input")),
            expected=_show(item.get("expected", "")),
            output=_show(output),
        )
        messages = [{"role": "user", "content": text}]
        response = asyncio.run(model.complete(messages, temperature=0.0))
        reply = _reply_text(response)
        meta = response if isinstance(response, dict) else {}
        value = judge_score(reply)
        run = Run(
            model_info=spec,
            user_prompt=text,
            tags=["eval-judge"],
            metadata={"eval_judge": {"item": item.get("id"), "scorer_version": version}},
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
        return value, run.id

    return Scorer("llm-judge", version, score, {"model": spec}, spent)


__all__ = ["DEFAULT_PROMPT", "judge_score", "judge_scorer"]
