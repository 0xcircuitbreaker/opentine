"""Git-shaped run graph operations above the trusted object kernel."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from opentine.kernel import parse_oid, validate_links
from opentine.repository._access import get_object as _get
from opentine.repository._run_graph import filtered_legacy_refs, graph_tips

if TYPE_CHECKING:
    from opentine.repository.store import Repo


@dataclass(frozen=True)
class LogEntry:
    oid: str
    object_type: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class SemanticDiff:
    common_events: tuple[str, ...]
    only_left: tuple[str, ...]
    only_right: tuple[str, ...]
    changed: tuple[dict[str, Any], ...]
    summary: dict[str, Any]


def _resolve(repo: Repo, value: str) -> str:
    try:
        parse_oid(value)
        return value
    except ValueError:
        resolved = repo.read_ref(value)
        if not resolved:
            raise KeyError(value)
        return resolved


def log(repo: Repo, ref: str = "heads/main", *, limit: int | None = None) -> list[LogEntry]:
    tip = _resolve(repo, ref)
    envelope = _get(repo, tip)
    if envelope.object_type == "run":
        payload = envelope.payload()
        queue = list(reversed(payload.get("tips") or payload.get("events") or []))
    else:
        queue = [tip]
    seen: set[str] = set()
    entries: list[LogEntry] = []
    while queue and (limit is None or len(entries) < limit):
        oid = queue.pop(0)
        if oid in seen:
            continue
        seen.add(oid)
        current = _get(repo, oid)
        payload = current.payload()
        entries.append(LogEntry(oid, current.object_type, payload))
        if current.object_type == "event":
            queue.extend(payload.get("parent_ids") or [])
    return entries


def _run_payload(repo: Repo, value: str) -> tuple[str, dict[str, Any]]:
    oid = _resolve(repo, value)
    envelope = _get(repo, oid)
    if envelope.object_type != "run":
        raise ValueError(f"expected run object, got {envelope.object_type}")
    return oid, envelope.payload()


def _metric(repo: Repo, events: list[str], name: str) -> float:
    total = 0.0
    for event in events:
        try:
            value = float(_get(repo, event).payload().get(name) or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        if math.isfinite(value):
            total += value
    return total


def _evaluations(repo: Repo, target: str) -> list[dict[str, Any]]:
    evaluations: list[dict[str, Any]] = []
    for oid in repo.iter_oids():
        if not oid.startswith("attestation:"):
            continue
        payload = _get(repo, oid).payload()
        claim = payload.get("claim") or {}
        if payload.get("target_id") == target and claim.get("kind") == "evaluation":
            evaluations.append({"attestation": oid, "scores": claim.get("scores") or {}})
    return evaluations


def semantic_diff(repo: Repo, left: str, right: str) -> SemanticDiff:
    left_id, left_run = _run_payload(repo, left)
    right_id, right_run = _run_payload(repo, right)
    left_events = list(left_run.get("events") or [])
    right_events = list(right_run.get("events") or [])
    right_set = set(right_events)
    common = tuple(event for event in left_events if event in right_set)
    common_set = set(common)
    only_left = tuple(event for event in left_events if event not in common_set)
    only_right = tuple(event for event in right_events if event not in common_set)
    changed: list[dict[str, Any]] = []
    for index in range(min(len(left_events), len(right_events))):
        left_event_id, right_event_id = left_events[index], right_events[index]
        if left_event_id == right_event_id:
            continue
        before = _get(repo, left_event_id).payload()
        after = _get(repo, right_event_id).payload()
        fields = [
            name
            for name in (
                "kind",
                "model",
                "cost",
                "duration",
                "usage",
                "billing",
                "input_blob",
                "output_blob",
                "artifact_blob",
                "tool",
            )
            if before.get(name) != after.get(name)
        ]
        changed.append(
            {
                "after": right_event_id,
                "before": left_event_id,
                "fields": fields,
                "index": index,
            }
        )
    summary = {
        "cost": {
            "left": _metric(repo, left_events, "cost"),
            "right": _metric(repo, right_events, "cost"),
        },
        "latency": {
            "left": _metric(repo, left_events, "duration"),
            "right": _metric(repo, right_events, "duration"),
        },
        "artifacts": {
            "left": [_get(repo, event).payload().get("artifact_blob") for event in left_events],
            "right": [_get(repo, event).payload().get("artifact_blob") for event in right_events],
        },
        "evaluations": {
            "left": _evaluations(repo, left_id),
            "right": _evaluations(repo, right_id),
        },
        "tool_path": {
            "left": [_get(repo, event).payload().get("tool") for event in left_events],
            "right": [_get(repo, event).payload().get("tool") for event in right_events],
        },
    }
    return SemanticDiff(common, only_left, only_right, tuple(changed), summary)


def context_slice(repo: Repo, event_id: str, *, depth: int = 8) -> list[LogEntry]:
    parse_oid(event_id)
    queue = [(event_id, 0)]
    found: list[LogEntry] = []
    seen: set[str] = set()
    while queue:
        oid, distance = queue.pop(0)
        if oid in seen or distance > depth:
            continue
        seen.add(oid)
        envelope = _get(repo, oid)
        payload = envelope.payload()
        found.append(LogEntry(oid, envelope.object_type, payload))
        if envelope.object_type == "event":
            links = [*(payload.get("parent_ids") or []), *(payload.get("causal_ids") or [])]
            queue.extend((link, distance + 1) for link in links)
    return list(reversed(found))


def fork_run(
    repo: Repo,
    run: str,
    from_event: str,
    *,
    overrides: dict[str, Any] | None = None,
    ref: str | None = None,
) -> str:
    source_id, payload = _run_payload(repo, run)
    if from_event not in payload.get("events", []):
        raise ValueError("fork event does not belong to source run")
    keep: set[str] = set()
    queue = [from_event]
    while queue:
        event = queue.pop()
        if event in keep:
            continue
        keep.add(event)
        event_payload = _get(repo, event).payload()
        queue.extend(event_payload.get("parent_ids") or [])
        queue.extend(event_payload.get("causal_ids") or [])
    forked = dict(payload)
    forked["legacy_refs"] = filtered_legacy_refs(payload, keep)
    forked.update(
        {
            "events": [event for event in payload["events"] if event in keep],
            "fork_overrides": overrides or {},
            "forked_from": source_id,
            "roots": [event for event in payload.get("roots", []) if event in keep],
            "status": "running",
        }
    )
    forked["tips"] = graph_tips(repo, forked["events"])
    run_id = repo.put("run", forked)
    if ref:
        repo.update_ref(ref, run_id, expected_old=repo.read_ref(ref))
    return run_id


def attest(
    repo: Repo,
    target_id: str,
    claim: dict[str, Any],
    *,
    signer: str,
    signature: dict[str, Any] | None = None,
    evidence_ids: list[str] | None = None,
) -> str:
    return repo.put(
        "attestation",
        {
            "claim": claim,
            "evidence_ids": evidence_ids or [],
            "signature": signature,
            "signer": signer,
            "target_id": target_id,
        },
    )


def promote(repo: Repo, run_id: str, name: str, *, expected_old: str | None = None) -> None:
    repo.update_ref(f"promotions/{name}", run_id, expected_old=expected_old)


def linked_objects(repo: Repo, oid: str) -> tuple[str, ...]:
    return validate_links(_get(repo, oid))
