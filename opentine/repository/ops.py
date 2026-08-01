"""Git-shaped run graph operations above the trusted object kernel."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from opentine.kernel import parse_oid, validate_links
from opentine.repository._access import get_object as _get
from opentine.repository._associations import evaluations as _evaluations
from opentine.repository._context import ContextBudget
from opentine.repository._diff_budget import DiffBudget
from opentine.repository._fork_state import fork_payload
from opentine.repository._shallow_read import ShallowBoundary
from opentine.repository._traversal import TraversalQueue

if TYPE_CHECKING:
    from opentine.repository.store import Repo


@dataclass(frozen=True)
class LogEntry:
    oid: str
    object_type: str
    payload: Any


@dataclass(frozen=True)
class SemanticDiff:
    common_events: tuple[str, ...]
    only_left: tuple[str, ...]
    only_right: tuple[str, ...]
    changed: tuple[dict[str, Any], ...]
    summary: dict[str, Any]


def resolve_target(repo: Repo, value: str) -> str:
    """Resolve a ref name or an object id to the object id it names.

    Public because every *write* verb must call it before the engine: ``attest``
    hands ``target_id`` to ``repo.put``, which requires an existing object, and
    ``promote`` hands its argument to ``update_ref``, which rejects a ref string.
    Signals "not here" with ``KeyError(<the name as given>)``.
    """
    try:
        parse_oid(value)
        return value
    except ValueError:
        resolved = repo.read_ref(value)
        if not resolved:
            raise KeyError(value)
        return resolved


def log(repo: Repo, ref: str = "heads/main", *, limit: int | None = None) -> list[LogEntry]:
    tip = resolve_target(repo, ref)
    boundary = ShallowBoundary(repo)
    if boundary.cuts(tip):
        return []
    envelope = _get(repo, tip)
    if envelope.object_type == "run":
        payload = envelope.payload()
        queue = TraversalQueue(
            (oid, 0) for oid in reversed(payload.get("tips") or payload.get("events") or [])
        )
    else:
        queue = TraversalQueue(((tip, 0),))
    entries: list[LogEntry] = []
    for oid, _ in queue:
        if limit is not None and len(entries) >= limit:
            break
        if boundary.cuts(oid):  # stop at the shallow-fetch boundary, like git log
            continue
        current = _get(repo, oid)
        payload = current.payload()
        entries.append(LogEntry(oid, current.object_type, payload))
        if current.object_type == "event":
            for parent in payload.get("parent_ids") or []:
                queue.add(parent)
    return entries


def _run_payload(repo: Repo, value: str, get=_get) -> tuple[str, dict[str, Any]]:
    oid = resolve_target(repo, value)
    if parse_oid(oid)[0] != "run":
        raise ValueError("operation requires a run object")
    envelope = get(repo, oid) if get is _get else get(oid)
    if envelope.object_type != "run":
        raise ValueError(f"expected run object, got {envelope.object_type}")
    return oid, envelope.payload()


def _metric(get, events: list[str], name: str) -> float:
    total = 0.0
    for event in events:
        try:
            value = float(get(event).payload().get(name) or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        if math.isfinite(value):
            total += value
    return total


def semantic_diff(repo: Repo, left: str, right: str) -> SemanticDiff:
    budget = DiffBudget(repo)
    get = budget.get
    boundary = ShallowBoundary(repo)
    left_id, left_run = _run_payload(repo, left, get)
    right_id, right_run = _run_payload(repo, right, get)
    left_events = list(left_run.get("events") or [])
    right_events = list(right_run.get("events") or [])
    left_present = boundary.present(left_events)
    right_present = boundary.present(right_events)
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
        if boundary.cuts(left_event_id) or boundary.cuts(right_event_id):
            continue  # a cut event's fields are unknowable; only_left/right keep the ids
        before = get(left_event_id).payload()
        after = get(right_event_id).payload()
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
            "left": _metric(get, left_present, "cost"),
            "right": _metric(get, right_present, "cost"),
        },
        "latency": {
            "left": _metric(get, left_present, "duration"),
            "right": _metric(get, right_present, "duration"),
        },
        "artifacts": {
            "left": [get(event).payload().get("artifact_blob") for event in left_present],
            "right": [get(event).payload().get("artifact_blob") for event in right_present],
        },
        "evaluations": {
            "left": _evaluations(repo, left_id, get),
            "right": _evaluations(repo, right_id, get),
        },
        "tool_path": {
            "left": [get(event).payload().get("tool") for event in left_present],
            "right": [get(event).payload().get("tool") for event in right_present],
        },
    }
    result = SemanticDiff(common, only_left, only_right, tuple(changed), summary)
    budget.check_output(result)
    return result


def context_slice(repo: Repo, event_id: str, *, depth: int = 8) -> list[LogEntry]:
    if parse_oid(event_id)[0] != "event":
        raise ValueError("context slices require an event id")
    if type(depth) is not int or depth < 0:
        raise ValueError("context depth must be a non-negative integer")
    queue = TraversalQueue(((event_id, 0),))
    budget = ContextBudget()
    boundary = ShallowBoundary(repo)
    found: list[LogEntry] = []
    for oid, distance in queue:
        if boundary.cuts(oid):  # stop at the shallow-fetch boundary, like git log
            continue
        envelope, payload = budget.event(repo, oid)
        found.append(LogEntry(oid, envelope.object_type, payload))
        if envelope.object_type == "event":
            links = [*(payload.get("parent_ids") or []), *(payload.get("causal_ids") or [])]
            if distance < depth:
                for link in links:
                    queue.add(link, distance + 1)
    return list(reversed(found))


def fork_run(
    repo: Repo,
    run: str,
    from_event: str,
    *,
    overrides: dict[str, Any] | None = None,
    ref: str | None = None,
) -> str:
    if parse_oid(from_event)[0] != "event":
        raise ValueError("fork point must be an event id")
    source_id, payload = _run_payload(repo, run)
    if from_event not in payload.get("events", []):
        raise ValueError("fork event does not belong to source run")
    forked = fork_payload(repo, source_id, payload, from_event, overrides)
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
