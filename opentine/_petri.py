"""Petri / Bloom transcripts as ``role=auditor`` runs (0.65).

A Petri transcript (``safety-research/petri``) records an auditor model
probing a target model and a judge scoring the result::

    {"metadata": {"transcript_id", "auditor_model", "target_model",
                  "judge_model"?, "description"?,
                  "judge_output": {"summary"?, "justification"?, "scores": {name: n}}},
     "events": [{"type": "transcript_event", "view": "target"|"auditor"|...,
                 "edit": {"operation": "add", "message": {"role", "content", ...}}}]}

Bloom transcripts use ``evaluator_model`` and an ``evaluator`` view; both are
read as the auditor. A transcript with a top-level ``messages`` list (each
message carrying ``view`` or ``source``) is read too.

The run is an ordinary run (no new object kind): tagged ``role=auditor`` and
``petri``; each message is a ``model`` step whose ``model_info`` is the model
that spoke (auditor, target, or the user/system text the auditor wrote); the
judge's scores are a final ``model`` step from the judge. ``metadata.audit``
names the three roles. With ``blind`` the target's identity is replaced by a
commitment (:mod:`opentine._audit_game`) so the auditor never sees it.

Parsing is pure and bounded: at most :data:`MAX_BYTES` of input, the import
guard's nesting and token budget, at most :data:`MAX_MESSAGES` messages.
"""

from __future__ import annotations

import json
import math
from typing import Any

from opentine.trace._import_guard import shape_checked

FORMAT = "petri"
MAX_BYTES = 16 * 1024 * 1024
MAX_MESSAGES = 10_000
MAX_TEXT = 1024 * 1024
AUDITOR, TARGET, JUDGE = "auditor", "target", "judge"
_AUDITOR_VIEWS = {"auditor", "evaluator"}


class PetriError(ValueError):
    """A transcript that cannot be read."""


def load(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_BYTES:
        raise PetriError(f"transcript exceeds {MAX_BYTES} bytes")
    try:
        doc = json.loads(shape_checked(data))
    except (ValueError, RecursionError) as exc:
        raise PetriError(f"transcript is not bounded JSON: {exc}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("metadata"), dict):
        raise PetriError("a Petri/Bloom transcript is an object with metadata")
    return doc


def _name(value: Any, default: str) -> str:
    return value[:256] if isinstance(value, str) and value else default


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content[:MAX_TEXT]
    if isinstance(content, list):
        parts = [c.get("text", "") for c in content if isinstance(c, dict)]
        return "".join(p for p in parts if isinstance(p, str))[:MAX_TEXT]
    return ""


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def messages(doc: dict[str, Any]) -> list[dict[str, str]]:
    """``[{speaker, role, text}]`` in order; speaker is auditor or target."""
    raw: list[tuple[str, Any]] = []
    for event in _list(doc.get("events")):
        if not isinstance(event, dict) or not isinstance(event.get("edit"), dict):
            continue
        edit = event["edit"]
        if edit.get("operation", "add") == "add" and isinstance(edit.get("message"), dict):
            raw.append((str(event.get("view", "target")), edit["message"]))
    if not raw:
        for message in _list(doc.get("messages")):
            if isinstance(message, dict):
                raw.append((str(message.get("view") or message.get("source") or ""), message))
    if len(raw) > MAX_MESSAGES:
        raise PetriError(f"transcript has more than {MAX_MESSAGES} messages")
    out = []
    for view, message in raw:
        role = _name(message.get("role"), "user")
        # In the target's view the auditor writes system, user and tool turns.
        speaker = TARGET if role == "assistant" and view not in _AUDITOR_VIEWS else AUDITOR
        out.append({"speaker": speaker, "role": role, "text": _text(message.get("content"))})
    return out


def roles(doc: dict[str, Any]) -> dict[str, Any]:
    meta = doc["metadata"]
    judge = meta.get("judge_output") if isinstance(meta.get("judge_output"), dict) else {}
    scores = judge.get("scores") if isinstance(judge.get("scores"), dict) else {}
    clean = {str(k)[:64]: v for k, v in list(scores.items())[:256]
             if isinstance(v, (int, float)) and not isinstance(v, bool)
             and math.isfinite(v)}  # fmt: skip
    return {
        "transcript": _name(meta.get("transcript_id"), "unknown"),
        AUDITOR: _name(meta.get("auditor_model") or meta.get("evaluator_model"), "unknown"),
        TARGET: _name(meta.get("target_model"), "unknown"),
        JUDGE: _name(meta.get("judge_model"), "unknown"),
        "scores": clean,
        "summary": _text(judge.get("summary")),
        "description": _text(meta.get("description") or meta.get("seed_instruction")),
    }


def to_run(doc: dict[str, Any], *, sealed: str | None = None) -> Any:
    """The ``role=auditor`` run; *sealed* replaces the target's identity."""
    from opentine.graph import Run, RunStatus, StepKind

    who = roles(doc)
    target = f"sealed:{sealed}" if sealed else who[TARGET]
    audit = {"role": AUDITOR, "source": FORMAT, "transcript": who["transcript"],
             "auditor_model": who[AUDITOR], "target_model": target,
             "judge_model": who[JUDGE], "scores": who["scores"]}  # fmt: skip
    run = Run(model_info=who[AUDITOR], user_prompt=who["description"] or "audit",
              tags=["role=auditor", FORMAT], metadata={"audit": audit})  # fmt: skip
    for message in messages(doc):
        model = target if message["speaker"] == TARGET else who[AUDITOR]
        run.add_step(StepKind.model, {"speaker": message["speaker"], "role": message["role"]},
                     {"text": message["text"]}, model_info=model)  # fmt: skip
    if who["scores"] or who["summary"]:
        run.add_step(StepKind.model, {"speaker": JUDGE, "role": "judge"},
                     {"scores": who["scores"], "text": who["summary"]},
                     model_info=who[JUDGE])  # fmt: skip
    run.status = RunStatus.completed
    return run


__all__ = ["AUDITOR", "FORMAT", "JUDGE", "MAX_BYTES", "PetriError", "TARGET", "load",
           "messages", "roles", "to_run"]  # fmt: skip
