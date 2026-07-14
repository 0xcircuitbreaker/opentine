"""Dependency-free local search across completed runs and evaluations."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opentine.repository.store import Repo


@dataclass(frozen=True)
class SearchResult:
    run_id: str
    status: str
    score: float | None
    cost: float
    latency: float
    models: tuple[str, ...]
    matched_text: str = ""


def _text(repo: Repo, event: dict[str, Any]) -> str:
    values: list[str] = []
    for field in ("input_blob", "output_blob"):
        oid = event.get(field)
        if not oid or not repo.has(oid):
            continue
        raw = repo.get(oid).body
        try:
            values.append(json.dumps(json.loads(raw), sort_keys=True))
        except (UnicodeDecodeError, json.JSONDecodeError):
            values.append(raw.decode(errors="replace"))
    return " ".join(values)


def search(
    repo: Repo,
    query: str = "",
    *,
    successful_only: bool = True,
    min_score: float | None = None,
    model: str | None = None,
    limit: int = 20,
) -> list[SearchResult]:
    scores: dict[str, list[float]] = {}
    for oid in repo.iter_oids():
        if not oid.startswith("attestation:"):
            continue
        payload = repo.get(oid).payload()
        claim = payload.get("claim") or {}
        if claim.get("kind") != "evaluation":
            continue
        values = [float(value) for value in (claim.get("scores") or {}).values()]
        if values:
            scores.setdefault(payload["target_id"], []).append(sum(values) / len(values))

    candidates = set(repo.list_refs().values())
    candidates.update(
        oid
        for oid in repo.iter_oids()
        if oid.startswith("run:")
        and repo.get(oid).payload().get("status") in {"completed", "failed"}
    )
    needle = query.casefold().strip()
    results: list[SearchResult] = []
    for run_id in candidates:
        envelope = repo.get(run_id)
        if envelope.object_type != "run":
            continue
        payload = envelope.payload()
        status = str(payload.get("status", "running"))
        if successful_only and status != "completed":
            continue
        events = [repo.get(oid).payload() for oid in payload.get("events") or [] if repo.has(oid)]
        models = tuple(sorted({str(event.get("model")) for event in events if event.get("model")}))
        if model and not any(model.casefold() in name.casefold() for name in models):
            continue
        text = " ".join(_text(repo, event) for event in events)
        if needle and needle not in text.casefold():
            continue
        run_scores = scores.get(run_id) or []
        score = max(run_scores) if run_scores else None
        if min_score is not None and (score is None or score < min_score):
            continue
        results.append(
            SearchResult(
                run_id,
                status,
                score,
                sum(float(event.get("cost") or 0) for event in events),
                sum(float(event.get("duration") or 0) for event in events),
                models,
                text[:240],
            )
        )
    results.sort(
        key=lambda item: (item.score is not None, item.score or 0, -item.cost),
        reverse=True,
    )
    return results[:limit]


def inspect(repo: Repo, oid: str, *, resolve_blobs: bool = False) -> dict[str, Any]:
    envelope = repo.get(oid)
    payload = envelope.payload()
    if isinstance(payload, bytes):
        try:
            payload = {"encoding": "utf-8", "text": payload.decode("utf-8")}
        except UnicodeDecodeError:
            payload = {
                "data": base64.b64encode(payload).decode("ascii"),
                "encoding": "base64",
            }
    result = {
        "id": oid,
        "payload": payload,
        "schema": envelope.schema,
        "type": envelope.object_type,
    }
    if resolve_blobs and isinstance(payload, dict):
        blobs: dict[str, Any] = {}
        for field, value in payload.items():
            if field.endswith("_blob") and isinstance(value, str) and repo.has(value):
                raw = repo.get(value).body
                try:
                    blobs[field] = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    blobs[field] = raw.decode(errors="replace")
        result["resolved_blobs"] = blobs
    return result
