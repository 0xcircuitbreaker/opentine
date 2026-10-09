"""Dependency-free local search across completed runs and evaluations."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from opentine.kernel import KernelError, ObjectEnvelope, validate_links
from opentine.repository._blob_io import read_verified_blob_prefix, stored_object_size
from opentine.repository._inspect import inspect as inspect
from opentine.repository._run_graph import validate_event_metrics
from opentine.repository._search_scores import best_score, collect_scores
from opentine.repository._semantic_view import CachedEnvelope

if TYPE_CHECKING:
    from opentine.repository.store import Repo

MAX_SEARCH_OBJECTS = 100_000
MAX_SEARCH_CANDIDATES = 10_000
MAX_SEARCH_EVENTS_PER_RUN = 10_000
MAX_SEARCH_EVENT_REFERENCES = 100_000
MAX_SEARCH_QUERY_CHARS = 4096
MAX_SEARCH_SOURCE_BYTES = 16 * 1024 * 1024
MAX_SEARCH_BLOB_BYTES = 4 * 1024 * 1024
MAX_SEARCH_TEXT_PER_RUN = 1024 * 1024
MAX_SEARCH_TEXT_TOTAL = 16 * 1024 * 1024
MAX_SEARCH_STRUCTURED_BYTES = 4 * 1024 * 1024
MAX_SEARCH_STRUCTURED_SOURCE_BYTES = 32 * 1024 * 1024


def _get_search_object(
    repo: Repo,
    oid: str,
    cache: dict[str, ObjectEnvelope],
    remaining: list[int],
) -> ObjectEnvelope:
    if oid in cache:
        return cache[oid]
    size = stored_object_size(repo, oid)
    if size > MAX_SEARCH_STRUCTURED_BYTES:
        raise ValueError("repository search encountered an oversized structured object")
    if size > remaining[0]:
        raise ValueError("repository search exceeds its aggregate structured-source limit")
    remaining[0] -= size
    envelope = CachedEnvelope(ObjectEnvelope.decode(repo.raw(oid), oid))
    validate_links(envelope)
    validate_event_metrics(envelope)
    cache[oid] = envelope
    return envelope


@dataclass(frozen=True)
class SearchResult:
    run_id: str
    status: str
    score: float | None
    cost: float
    latency: float
    models: tuple[str, ...]
    matched_text: str = ""
    #: Whether a signed evaluation decided ``score`` (None without one); see
    #: _search_scores. Signed is not verified: search holds no keys.
    score_signed: bool | None = None


def _finite(value: Any, default: float | None = None) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if math.isfinite(number) else default


def _blob_text(
    repo: Repo,
    oid: str,
    cache: dict[str, tuple[str, int]],
    remaining_source: list[int],
) -> tuple[str, int]:
    if oid in cache:
        return cache[oid]
    maximum = min(MAX_SEARCH_BLOB_BYTES, remaining_source[0])
    if maximum < 1:
        raise ValueError("repository search exceeds its aggregate source-byte limit")
    raw, total, _ = read_verified_blob_prefix(
        repo, oid, prefix_limit=maximum, source_limit=maximum,
    )  # fmt: skip
    remaining_source[0] -= total
    text = raw.decode("utf-8", errors="replace")
    cache[oid] = (text, total)
    return cache[oid]


def _search_event_text(
    repo: Repo,
    events: list[dict[str, Any]],
    needle: str,
    cache: dict[str, tuple[str, int]],
    remaining_source: list[int],
    remaining_text: list[int],
) -> tuple[bool, str]:
    seen: set[str] = set()
    preview = ""
    retained = 0
    for event in events:
        for field in ("input_blob", "output_blob"):
            oid = event.get(field)
            if not isinstance(oid, str) or oid in seen or not repo.has(oid):
                continue
            seen.add(oid)
            text, _ = _blob_text(repo, oid, cache, remaining_source)
            remaining = MAX_SEARCH_TEXT_PER_RUN - retained
            if remaining <= 0:
                raise ValueError("repository search exceeds its per-run text limit")
            kept = text[:remaining]
            if len(kept) > remaining_text[0]:
                raise ValueError("repository search exceeds its aggregate text limit")
            remaining_text[0] -= len(kept)
            retained += len(kept)
            if not preview:
                preview = kept[:240]
            if needle in kept.casefold():
                return True, preview
            if len(text) > remaining:
                raise ValueError("repository search exceeds its per-run text limit")
    return False, preview


def search(
    repo: Repo,
    query: str = "",
    *,
    successful_only: bool = True,
    min_score: float | None = None,
    model: str | None = None,
    limit: int = 20,
    signed_only: bool = False,
) -> list[SearchResult]:
    if not isinstance(query, str):
        raise TypeError("search query must be a string")
    if len(query) > MAX_SEARCH_QUERY_CHARS:
        raise ValueError("search query exceeds the 4096-character limit")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("search limit must be between 1 and 1000")
    oids = repo.iter_oids(limit=MAX_SEARCH_OBJECTS)
    object_cache: dict[str, ObjectEnvelope] = {}
    structured_remaining = [MAX_SEARCH_STRUCTURED_SOURCE_BYTES]

    def attestation_payload(oid: str) -> dict[str, Any] | None:
        try:
            return _get_search_object(repo, oid, object_cache, structured_remaining).payload()
        except (KernelError, KeyError, OSError):
            return None

    scores = collect_scores(oids, attestation_payload, _finite)
    try:
        # Runs only: a tags/* ref on a big blob otherwise spent the budget and raised.
        candidates = {oid for oid in repo.list_refs().values() if oid.startswith("run:")}
    except (KernelError, OSError, UnicodeError, ValueError):
        candidates = set()
    for oid in oids:
        if not oid.startswith("run:"):
            continue
        try:
            payload = _get_search_object(repo, oid, object_cache, structured_remaining).payload()
        except (KernelError, KeyError, OSError):
            continue
        if payload.get("status") in {"completed", "failed"}:
            candidates.add(oid)
    if len(candidates) > MAX_SEARCH_CANDIDATES:
        raise ValueError("repository search exceeds its candidate-run limit")
    needle = query.casefold().strip()
    results: list[SearchResult] = []
    blob_cache: dict[str, tuple[str, int]] = {}
    remaining_source = [MAX_SEARCH_SOURCE_BYTES]
    remaining_text = [MAX_SEARCH_TEXT_TOTAL]
    remaining_events = MAX_SEARCH_EVENT_REFERENCES
    for run_id in sorted(candidates):
        try:
            envelope = _get_search_object(repo, run_id, object_cache, structured_remaining)
        except (KernelError, KeyError, OSError, ValueError):
            # One unusable object must not end the search for every other run.
            continue
        if envelope.object_type != "run":
            continue
        payload = envelope.payload()
        status = str(payload.get("status", "running"))
        if successful_only and status != "completed":
            continue
        event_ids = payload.get("events") or []
        if len(event_ids) > MAX_SEARCH_EVENTS_PER_RUN:
            raise ValueError("repository search exceeds its per-run event limit")
        remaining_events -= len(event_ids)
        if remaining_events < 0:
            raise ValueError("repository search exceeds its aggregate event-reference limit")
        events = []
        for oid in event_ids:
            try:
                events.append(
                    _get_search_object(repo, oid, object_cache, structured_remaining).payload()
                )
            except (KernelError, KeyError, OSError):
                continue
        models = tuple(sorted({str(event.get("model")) for event in events if event.get("model")}))
        if model and not any(model.casefold() in name.casefold() for name in models):
            continue
        matched_text = ""
        if needle:
            matched, matched_text = _search_event_text(
                repo, events, needle, blob_cache, remaining_source, remaining_text
            )
            if not matched:
                continue
        score, score_signed = best_score(scores.get(run_id) or [], signed_only=signed_only)
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
                matched_text,
                score_signed,
            )
        )
    # run_id tiebreak: a candidate set iterates in hash order, so equally ranked
    # runs gave a different top-N per process for an unchanged repository.
    # A signed score outranks any unsigned one: unsigned is anyone's say-so.
    results.sort(
        key=lambda item: (
            0 if item.score is not None else 1,
            0 if item.score_signed else 1,
            -(item.score or 0),
            item.cost,
            item.run_id,
        )
    )
    return results[:limit]
