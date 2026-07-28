"""Incremental persistence for recorder-generated run snapshots."""

from __future__ import annotations

from typing import Any

from opentine.kernel import KernelError, ObjectEnvelope, validate_links

_MUTABLE_FIELDS = {"events", "finished_at", "roots", "status", "tips"}


def _validate_transition(
    repo: Any,
    previous: dict[str, Any],
    updated: dict[str, Any],
    envelope: ObjectEnvelope,
) -> None:
    validate_links(envelope)
    for field in set(previous) | set(updated):
        if field not in _MUTABLE_FIELDS and (
            field not in previous or field not in updated or previous[field] != updated[field]
        ):
            raise KernelError(f"recorder transition cannot change run field {field!r}")
    old_events = list(previous.get("events") or [])
    events = list(updated.get("events") or [])
    if events[: len(old_events)] != old_events:
        raise KernelError("recorder transition must append to the existing event sequence")
    positions = {oid: index for index, oid in enumerate(events)}
    roots = list(previous.get("roots") or [])
    tips = list(previous.get("tips") or [])
    for index, oid in enumerate(events[len(old_events) :], len(old_events)):
        event = repo.get(oid)
        payload = event.payload()
        if event.object_type != "event" or not isinstance(payload, dict):
            raise KernelError("recorder run entries must resolve to events")
        parents = list(payload.get("parent_ids") or [])
        causal = list(payload.get("causal_ids") or [])
        if any(link not in positions or positions[link] >= index for link in [*parents, *causal]):
            raise KernelError("recorder event dependencies must precede it in the run")
        if not parents:
            roots.append(oid)
        tips = [tip for tip in tips if tip not in parents]
        tips.append(oid)
    if updated.get("roots") != roots or updated.get("tips") != tips:
        raise KernelError("recorder transition has invalid roots or tips")
    if updated.get("status", "running") not in {"running", "paused", "completed", "failed"}:
        raise KernelError("recorder transition has an invalid status")


def advance_run(
    repo: Any,
    ref: str,
    current: str,
    previous: dict[str, Any],
    payload: dict[str, Any],
) -> str:
    """Persist a deterministically updated run without rewalking prior events."""
    envelope = ObjectEnvelope.create("run", payload)
    _validate_transition(repo, previous, payload, envelope)
    store = getattr(repo, "_store_envelope", None)
    update = getattr(repo, "_update_ref_validated", None)
    if callable(store) and callable(update):
        next_run = store(envelope)
        update(ref, next_run, envelope, expected_old=current)
        return next_run
    next_run = repo.put("run", payload)
    repo.update_ref(ref, next_run, expected_old=current)
    return next_run
