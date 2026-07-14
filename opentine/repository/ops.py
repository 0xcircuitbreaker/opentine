"""Git-shaped run graph operations above the trusted object kernel."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from opentine.kernel import parse_oid, validate_links

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
    envelope = repo.get(tip)
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
        current = repo.get(oid)
        payload = current.payload()
        entries.append(LogEntry(oid, current.object_type, payload))
        if current.object_type == "event":
            queue.extend(payload.get("parent_ids") or [])
    return entries


def _run_payload(repo: Repo, value: str) -> tuple[str, dict[str, Any]]:
    oid = _resolve(repo, value)
    envelope = repo.get(oid)
    if envelope.object_type != "run":
        raise ValueError(f"expected run object, got {envelope.object_type}")
    return oid, envelope.payload()


def _metric(repo: Repo, events: list[str], name: str) -> float:
    return sum(float(repo.get(event).payload().get(name) or 0) for event in events)


def semantic_diff(repo: Repo, left: str, right: str) -> SemanticDiff:
    _, left_run = _run_payload(repo, left)
    _, right_run = _run_payload(repo, right)
    left_events = list(left_run.get("events") or [])
    right_events = list(right_run.get("events") or [])
    common = tuple(event for event in left_events if event in set(right_events))
    only_left = tuple(event for event in left_events if event not in set(common))
    only_right = tuple(event for event in right_events if event not in set(common))
    changed: list[dict[str, Any]] = []
    for index in range(min(len(left_events), len(right_events))):
        left_id, right_id = left_events[index], right_events[index]
        if left_id == right_id:
            continue
        before = repo.get(left_id).payload()
        after = repo.get(right_id).payload()
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
                "tool",
            )
            if before.get(name) != after.get(name)
        ]
        changed.append({"after": right_id, "before": left_id, "fields": fields, "index": index})
    summary = {
        "cost": {
            "left": _metric(repo, left_events, "cost"),
            "right": _metric(repo, right_events, "cost"),
        },
        "latency": {
            "left": _metric(repo, left_events, "duration"),
            "right": _metric(repo, right_events, "duration"),
        },
        "tool_path": {
            "left": [repo.get(event).payload().get("tool") for event in left_events],
            "right": [repo.get(event).payload().get("tool") for event in right_events],
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
        envelope = repo.get(oid)
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
        queue.extend(repo.get(event).payload().get("parent_ids") or [])
    forked = dict(payload)
    forked.update(
        {
            "events": [event for event in payload["events"] if event in keep],
            "fork_overrides": overrides or {},
            "forked_from": source_id,
            "roots": [event for event in payload.get("roots", []) if event in keep],
            "status": "running",
            "tips": [from_event],
        }
    )
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
    return validate_links(repo.get(oid))
