"""``tine import --format jules``: a Jules session export as a run (0.49).

Jules (Google's asynchronous coding agent) exposes a session through its REST
API (``jules.googleapis.com/v1alpha``): ``GET sessions/{id}`` (``prompt``,
``title``, ``sourceContext``, ``state``, ``url``) and ``GET
sessions/{id}/activities`` (``{"activities": [...], "nextPageToken"}``). An
export is the activities response on its own, a bare list of activities, or
``{"session": {...}, "activities": [...]}``; pages saved as JSONL (one response
per line) are concatenated. Each Activity carries one of ``agentMessaged``,
``userMessaged``, ``planGenerated``, ``planApproved``, ``progressUpdated``,
``sessionCompleted`` or ``sessionFailed``, plus ``artifacts``
(``changeSet.gitPatch``, ``bashOutput``, ``media``). Mapping:

* the session ``prompt`` and ``userMessaged`` -> ``human`` steps;
* ``agentMessaged``, ``planGenerated``, ``progressUpdated`` -> ``model`` steps
  (model ``jules``, provider ``google``; Jules reports no token usage, so none
  is recorded);
* ``planApproved`` -> an ``approval`` step; ``sessionFailed`` -> ``error``;
* ``bashOutput`` -> a ``tool`` step (actor ``bash``); ``changeSet`` -> a
  ``tool`` step (actor ``jules.change_set``) with the patch, base commit and
  suggested message; ``media`` -> a ``tool`` step with the MIME type and size
  only (the bytes are not imported).

Deferred: the Jules web UI has no documented export; only the API shapes above
are read. Every payload goes through redaction before it is recorded.
"""

from __future__ import annotations

import binascii
import json
from typing import Any

from opentine.redaction import redact_value
from opentine.trace._import_guard import shape_checked
from opentine.trace._transcript_common import bounded_id, event
from opentine.trace.schema import TraceEvent

MAX_ACTIVITIES = 100_000
TEXT = 1 << 20
KINDS = ("agentMessaged", "userMessaged", "planGenerated", "planApproved",
         "progressUpdated", "sessionCompleted", "sessionFailed")  # fmt: skip


def documents(raw: bytes) -> list[Any]:
    """One JSON document (a list is spread) or one per JSONL line."""
    text = shape_checked(raw).decode("utf-8-sig")  # type: ignore[union-attr]
    try:
        decoded: Any = json.loads(text)
    except ValueError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return decoded if isinstance(decoded, list) else [decoded]


def _split(docs: list[Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    session: dict[str, Any] = {}
    activities: list[dict[str, Any]] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        if any(key in doc for key in KINDS):
            activities.append(doc)
            continue
        if isinstance(doc.get("session"), dict):
            session = doc["session"]
        elif "prompt" in doc and "sourceContext" in doc:
            session = doc
        activities.extend(item for item in doc.get("activities") or [] if isinstance(item, dict))
    if not activities and not session:
        raise ValueError("no activities and no session")
    return session, activities[:MAX_ACTIVITIES]


def _clip(value: Any, limit: int = TEXT) -> str:
    return str(value or "")[:limit]


def _get(container: dict[str, Any], key: str) -> dict[str, Any]:
    value = container.get(key)
    return value if isinstance(value, dict) else {}


def _artifact(art: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]] | None:
    if "bashOutput" in art:
        bash = _get(art, "bashOutput")
        return (
            "bash",
            {"command": _clip(bash.get("command"))},
            {"output": _clip(bash.get("output")), "exit_code": bash.get("exitCode")},
        )
    if "changeSet" in art:
        change = _get(art, "changeSet")
        patch = _get(change, "gitPatch")
        return ("jules.change_set", {"source": _clip(change.get("source"), 1024)}, {
            "patch": _clip(patch.get("unidiffPatch")),
            "base_commit": _clip(patch.get("baseCommitId"), 64),
            "suggested_commit_message": _clip(patch.get("suggestedCommitMessage"))})  # fmt: skip
    if "media" in art:
        media = _get(art, "media")
        try:
            size: int | None = len(binascii.a2b_base64(str(media.get("data") or "")))
        except (binascii.Error, ValueError):
            size = None
        return ("jules.media", {}, {"mime_type": _clip(media.get("mimeType"), 128), "bytes": size})
    return None


def _step(act: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    if "userMessaged" in act:
        text = _clip(_get(act, "userMessaged").get("userMessage"))
        return "human", {"actor": "user", "inputs": {"role": "user", "text": text}}
    if "agentMessaged" in act:
        return "model", {"outputs": {"text": _clip(_get(act, "agentMessaged").get("agentMessage"))}}
    if "planGenerated" in act:
        plan = _get(_get(act, "planGenerated"), "plan")
        steps = [{"title": _clip(s.get("title"), 1024), "description": _clip(s.get("description"))}
                 for s in plan.get("steps") or [] if isinstance(s, dict)]  # fmt: skip
        return "model", {"outputs": {"plan_id": _clip(plan.get("id"), 256), "steps": steps}}
    if "progressUpdated" in act:
        done = _get(act, "progressUpdated")
        return "model", {"outputs": {"title": _clip(done.get("title")),
                                     "description": _clip(done.get("description"))}}  # fmt: skip
    if "planApproved" in act:
        plan_id = _clip(_get(act, "planApproved").get("planId"), 256)
        return "approval", {"actor": "user", "inputs": {"plan_id": plan_id}}
    if "sessionFailed" in act:
        return "error", {"outputs": {"reason": _clip(_get(act, "sessionFailed").get("reason"))}}
    return None


def jules_events(data: bytes | str) -> list[TraceEvent]:
    """Events for one Jules session (its prompt, activities and artifacts)."""
    raw = data.encode() if isinstance(data, str) else data
    try:
        session, activities = _split(documents(raw))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"not a Jules session export: {exc}") from exc
    first = str(activities[0].get("name") or "") if activities else ""
    trace = bounded_id(session.get("id") or first.split("/activities")[0] or "session", "jules")
    base = {"jules.state": _clip(session.get("state"), 64)}
    if session.get("url"):
        base["jules.url"] = _clip(session["url"], 2048)
    events: list[TraceEvent] = []
    if session.get("prompt"):
        prompt = redact_value({"role": "user", "text": _clip(session["prompt"])})
        events.append(event("human", session.get("createTime"), trace, "prompt", actor="user",
                            inputs=prompt, attributes=base))  # fmt: skip
    for number, act in enumerate(activities):
        when, span = act.get("createTime"), f"activity-{number}"
        attrs = {**base, "jules.originator": _clip(act.get("originator"), 32)}
        step = _step(act)
        if step is not None:
            kind, fields = step
            if kind == "model":
                fields = {**fields, "model": "jules", "provider": "google"}
            for key in ("inputs", "outputs"):
                if key in fields:
                    fields[key] = redact_value(fields[key])
            events.append(event(kind, when, trace, span, attributes=attrs, **fields))
        for index, art in enumerate(act.get("artifacts") or []):
            found = _artifact(art) if isinstance(art, dict) else None
            if found is not None:
                actor, inputs, outputs = found
                events.append(event("tool", when, trace, f"{span}-artifact-{index}",
                                    parent=span if step else None,
                                    actor=actor, inputs=redact_value(inputs),
                                    outputs=redact_value(outputs), attributes=attrs))  # fmt: skip
    if not events:
        raise ValueError("Jules session export holds no prompt, message or artifact")
    return events


__all__ = ["KINDS", "documents", "jules_events"]
