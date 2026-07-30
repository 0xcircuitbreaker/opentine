"""Span-map construction for recorder runs, shallow-fetch boundary aware.

Continuing a run must read every event it already contains (a full
materialization, like load_run), so on a depth-limited clone these builders
refuse with the same typed KernelError remedy instead of leaking the raw
KeyError the object store raises for the first cut event.
"""

from __future__ import annotations

from typing import Any

from opentine.repository._shallow_read import require_deep
from opentine.trace._record_event import SpanMap, span_key


def validated_span_map(
    repo: Any,
    run_id: str,
    events: set[str],
    span_map: SpanMap,
) -> SpanMap:
    """Check a caller-supplied span map against the run it claims to index."""
    accepted = dict(span_map)
    require_deep(repo, accepted.values(), f"recording into run {run_id}")
    for key, event_id in accepted.items():
        if event_id not in events:
            raise ValueError("recorder span map contains an event outside the run")
        event = repo.get(event_id).payload()
        if key != span_key(event.get("trace_id", ""), event.get("span_id")):
            raise ValueError("recorder span map key does not match its event")
    return accepted


def resumed_span_map(repo: Any, run_id: str, events: list[str]) -> SpanMap:
    """Rebuild the span map for every event already recorded in a run."""
    require_deep(repo, events, f"resuming run {run_id}")
    span_map: SpanMap = {}
    for event in events:
        payload = repo.get(event).payload()
        span_id = payload.get("span_id")
        if span_id is None:
            continue
        key = span_key(payload.get("trace_id", ""), span_id)
        if key in span_map:
            raise ValueError(f"duplicate span ID within trace: {key[1]!r}")
        span_map[key] = event
    return span_map
