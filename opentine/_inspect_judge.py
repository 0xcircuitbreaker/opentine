"""Judge provenance for imported Inspect scorers (0.65).

A model-graded Inspect scorer (``model_graded_qa``, ``model_graded_fact`` and the
like) records its arguments in the log header under
``results.scores[].params``: the grader ``model``, the ``template`` and the
``instructions``. Newer logs name the grader under ``eval.model_roles.grader``.
When the log names a grader model, the importer turns that into an
``opentine.judge-provenance/1`` document, signs its ``jp1+sha256:`` pin as the
verdicts' ``scorer_version`` and writes it beside them as ``judge.json``, so
``tine eval verify`` catches a swapped template, rubric or grader afterwards.

What goes in, read only from the log (nothing is guessed):

- ``model``: ``params.model`` when it is a string, else
  ``eval.model_roles.grader.model``. No grader model: no provenance.
- ``prompt``: ``params.template`` when it is a string, else the canonical JSON
  of the recorded params without ``model`` (the scorer's own default template
  is not in the log, so its digest covers the arguments that were given).
- ``rubric``: ``params.instructions`` when it is a string.
- ``sampling``: the finite numeric fields of the grader's ``config``
  (``temperature``, ``top_p``, ``max_tokens``...); ``temperature`` is 0 when
  the log records none (the convention's default).
"""

from __future__ import annotations

import json
import math
from typing import Any

from opentine import _judge_provenance as jp


def _grader(log: dict[str, Any]) -> dict[str, Any]:
    roles = log.get("eval", {}).get("model_roles")
    grader = roles.get("grader") if isinstance(roles, dict) else None
    return grader if isinstance(grader, dict) else {}


def _params(log: dict[str, Any], name: str) -> dict[str, Any] | None:
    results = log.get("results") or {}
    scores = results.get("scores") if isinstance(results, dict) else None
    for entry in scores if isinstance(scores, list) else []:
        if isinstance(entry, dict) and entry.get("name") == name:
            params = entry.get("params")
            return params if isinstance(params, dict) else None
    return None


def _sampling(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in sorted(config.items()):
        if len(out) >= jp.MAX_PARAMS - 1 or not jp._PARAM.fullmatch(str(key)):
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        if isinstance(value, float) and not math.isfinite(value):
            continue
        out[str(key)] = value
    return out


def provenance(log: dict[str, Any], name: str) -> dict[str, Any] | None:
    """The judge provenance of scorer *name* in *log*, or ``None`` when it names no grader."""
    params = _params(log, name)
    if params is None:
        return None
    grader = _grader(log)
    model = params.get("model")
    if not isinstance(model, str):
        model = grader.get("model")
    if not isinstance(model, str) or not 0 < len(model) <= 256:
        return None
    template = params.get("template")
    if isinstance(template, str):
        prompt = template
    else:
        rest = {k: v for k, v in params.items() if k != "model"}
        prompt = json.dumps(rest, sort_keys=True, ensure_ascii=False, default=str)
    rubric = params.get("instructions")
    try:
        return jp.build(model, prompt, rubric=rubric if isinstance(rubric, str) else None,
                        sampling=_sampling(grader.get("config")))  # fmt: skip
    except (ValueError, TypeError, ArithmeticError):
        return None


def provenances(log: dict[str, Any], names: list[str]) -> dict[str, dict[str, Any]]:
    """``{scorer: provenance}`` for the scorers of *names* whose grader the log names."""
    out = {}
    for name in names:
        doc = provenance(log, name)
        if doc is not None:
            out[name] = doc
    return out


__all__ = ["provenance", "provenances"]
