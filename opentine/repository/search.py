"""Dependency-free local search across completed runs and evaluations."""

from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from opentine.kernel import KernelError

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


def _finite(value: Any, default: float | None = None) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if math.isfinite(number) else default


def _text(repo: Repo, event: dict[str, Any]) -> str:
    values: list[str] = []
    for field in ("input_blob", "output_blob"):
        oid = event.get(field)
        if not oid or not repo.has(oid):
            continue
        try:
            raw = repo.get(oid).body
        except (KernelError, KeyError, OSError):
            continue
        try:
            values.append(json.dumps(json.loads(raw), sort_keys=True))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
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
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("search limit must be between 1 and 1000")
    scores: dict[str, list[float]] = {}
    for oid in repo.iter_oids():
        if not oid.startswith("attestation:"):
            continue
        try:
            payload = repo.get(oid).payload()
        except (KernelError, KeyError, OSError):
            continue
        claim = payload.get("claim") or {}
        if not isinstance(claim, dict) or not isinstance(claim.get("scores") or {}, dict):
            continue
        if claim.get("kind") != "evaluation":
            continue
        values = [
            number
            for value in (claim.get("scores") or {}).values()
            if (number := _finite(value)) is not None
        ]
        target = payload.get("target_id")
        average = _finite(sum(values) / len(values)) if values else None
        if isinstance(target, str) and average is not None:
            scores.setdefault(target, []).append(average)

    try:
        candidates = set(repo.list_refs().values())
    except (KernelError, OSError, UnicodeError, ValueError):
        candidates = set()
    for oid in repo.iter_oids():
        if not oid.startswith("run:"):
            continue
        try:
            payload = repo.get(oid).payload()
        except (KernelError, KeyError, OSError):
            continue
        if payload.get("status") in {"completed", "failed"}:
            candidates.add(oid)
    needle = query.casefold().strip()
    results: list[SearchResult] = []
    for run_id in candidates:
        try:
            envelope = repo.get(run_id)
        except (KernelError, KeyError, OSError):
            continue
        if envelope.object_type != "run":
            continue
        payload = envelope.payload()
        status = str(payload.get("status", "running"))
        if successful_only and status != "completed":
            continue
        events = []
        for oid in payload.get("events") or []:
            try:
                events.append(repo.get(oid).payload())
            except (KernelError, KeyError, OSError):
                continue
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
                sum(_finite(event.get("cost"), 0) or 0 for event in events),
                sum(_finite(event.get("duration"), 0) or 0 for event in events),
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
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                    blobs[field] = raw.decode(errors="replace")
        result["resolved_blobs"] = blobs
    return result
