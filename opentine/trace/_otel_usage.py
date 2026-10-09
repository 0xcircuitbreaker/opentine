"""GenAI token counters in, current-convention counters out, and agent roll-ups.

Two readings of the same attribute names are in the wild, and they price
differently:

* the **deployed** spellings (``gen_ai.usage.cache_read_input_tokens`` and the
  rest of :data:`~opentine.trace._genai_semconv.USAGE_BY_DIMENSION`) carry
  *exclusive* buckets beside ``input_tokens`` -- what every OpenTine export up to
  0.8.1 wrote, so they keep that reading and old documents import unchanged;
* the **current convention** (:data:`~opentine.trace._genai_semconv.STANDARD_USAGE_KEYS`)
  reports *inclusive* totals with sub-counts inside them. Reading those the
  deployed way billed 90k cached tokens at the full input rate, a 4.4x
  overcharge on an ordinary cached call.

Export writes the current convention, so Langfuse, Phoenix and every other
reader see totals that include cached and reasoning tokens, and adds the exact
usage under :data:`~opentine.trace._genai_semconv.USAGE_ATTRIBUTE` only when the
standard counters cannot carry it back.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from opentine.trace import _genai_semconv as semconv
from opentine.trace._import_helpers import event_kind, imported_usage, note_import_warning

_MAX_SAFE_INTEGER = (1 << 53) - 1
_LEGACY_KEYS = frozenset(semconv.USAGE_BY_DIMENSION.values())
_COUNTER_KEYS = _LEGACY_KEYS | set(semconv.STANDARD_USAGE_KEYS) | {semconv.USAGE_ATTRIBUTE}


def otel_kind(operation: str) -> str:
    """The kind an operation name implies; agent operations are ``subagent``."""
    return "subagent" if operation in semconv.AGENT_OPERATIONS else event_kind(operation)


def span_kind(attributes: dict[str, Any], operation: str, inferred: set[int], position: int) -> str:
    """A span's kind: an explicit ``opentine.trace.kind`` (consumed), else its operation's.

    Agent spans whose kind was only inferred are noted in *inferred* for
    :func:`bill_unreported_agents` to reconsider once every span is read.
    """
    explicit = str(attributes.pop(semconv.KIND_ATTRIBUTE, ""))
    if explicit:
        return explicit
    if operation in semconv.AGENT_OPERATIONS:
        inferred.add(position)
    return otel_kind(operation)


def otel_usage(attributes: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read the token counters a span carries into OpenTine's exclusive buckets.

    Only counters present on the span become dimensions: a span that reported no
    usage imports with empty usage rather than invented zeros.
    """
    exact = attributes.get(semconv.USAGE_ATTRIBUTE)
    if isinstance(exact, dict):
        usage, attributes = imported_usage(exact, attributes)
        # Consumed, like cost and billing: export writes it back from the event
        # whenever the counters alone would not reproduce this usage.
        del attributes[semconv.USAGE_ATTRIBUTE]
        return usage, attributes
    raw = {
        name: attributes[key]
        for name, key in semconv.USAGE_BY_DIMENSION.items()
        if key in attributes
    }
    _apply_standard_counters(attributes, raw)
    return imported_usage(raw, attributes)


def _tokens(value: Any) -> int | None:
    if type(value) is float and value.is_integer():
        value = int(value)
    return value if type(value) is int and 0 <= value <= _MAX_SAFE_INTEGER else None


def _apply_standard_counters(attributes: dict[str, Any], raw: dict[str, Any]) -> None:
    read = _tokens(attributes.get(semconv.CACHE_READ_INPUT_TOKENS))
    write = next(
        (
            count
            for key in semconv.CACHE_WRITE_KEYS
            if (count := _tokens(attributes.get(key))) is not None
        ),
        None,
    )
    if read is not None or write is not None:
        # The current convention names no cache TTL, so a write is the default
        # (5-minute) write; the deployed cache keys, if a span mixes both
        # spellings, are superseded rather than added on top.
        for name in ("cache_read", "cache_write_5m", "cache_write_1h"):
            raw.pop(name, None)
        if read is not None:
            raw["cache_read"] = read
        if write is not None:
            raw["cache_write_5m"] = write
        _subtract(attributes, raw, "input", semconv.INPUT_TOKENS, (read or 0) + (write or 0))
    reasoning = _tokens(attributes.get(semconv.REASONING_OUTPUT_TOKENS))
    if reasoning is not None:
        raw["reasoning"] = reasoning
        _subtract(attributes, raw, "output", semconv.OUTPUT_TOKENS, reasoning)


def _subtract(
    attributes: dict[str, Any], raw: dict[str, Any], name: str, key: str, included: int
) -> None:
    total = _tokens(attributes.get(key))
    if total is None:
        return
    if total >= included:
        raw[name] = total - included
        return
    # A total smaller than its own sub-counts cannot include them: the emitter
    # reported exclusive buckets under the inclusive names. Keep its number
    # rather than invent a negative, and say so on the span.
    raw[name] = total
    note_import_warning(attributes, f"{key} is smaller than its sub-counts; read as exclusive")


def usage_attributes(usage: dict[str, Any], attributes: dict[str, Any]) -> dict[str, Any]:
    """The usage attributes an exported span still needs.

    A span that already carries counters -- an imported one, whose attributes
    travel verbatim -- gets none derived, so it re-exports to the bytes it came
    from; anything else gets current-convention counters. Either way the exact
    usage is added when reading the result back would not reproduce *usage*.
    """
    if not usage:
        return {}
    added = {} if _COUNTER_KEYS & set(attributes) else _standard_counters(usage)
    read_back, _ = otel_usage({**attributes, **added})
    if read_back != dict(usage):
        added[semconv.USAGE_ATTRIBUTE] = dict(usage)
    return added


def _standard_counters(usage: dict[str, Any]) -> dict[str, int]:
    count = {name: _tokens(usage.get(name)) for name in semconv.USAGE_BY_DIMENSION}
    writes = None
    if count["cache_write_5m"] is not None or count["cache_write_1h"] is not None:
        writes = (count["cache_write_5m"] or 0) + (count["cache_write_1h"] or 0)
    counters: dict[str, int] = {}
    if any(value is not None for value in (count["input"], count["cache_read"], writes)):
        counters[semconv.INPUT_TOKENS] = (
            (count["input"] or 0) + (count["cache_read"] or 0) + (writes or 0)
        )
    if count["cache_read"] is not None:
        counters[semconv.CACHE_READ_INPUT_TOKENS] = count["cache_read"]
    if writes is not None:
        counters[semconv.CACHE_CREATION_INPUT_TOKENS] = writes
    if count["output"] is not None or count["reasoning"] is not None:
        counters[semconv.OUTPUT_TOKENS] = (count["output"] or 0) + (count["reasoning"] or 0)
    if count["reasoning"] is not None:
        counters[semconv.REASONING_OUTPUT_TOKENS] = count["reasoning"]
    if count["total"] is not None:
        counters[semconv.TOTAL_TOKENS] = count["total"]
    return counters


def bill_unreported_agents(events: list[Any], inferred: set[int]) -> list[Any]:
    """Re-kind as ``model`` the agent spans whose usage nothing beneath re-reports.

    An agent span's counters usually aggregate the model calls under it; billing
    both double-charged every agent run. When no descendant reports usage of its
    own -- a remote agent, or an emitter that records only the agent -- the
    agent span is the only record of that spend and must be billed. Only kinds
    *inferred* from the operation name are reconsidered (an explicit
    ``opentine.trace.kind`` is authoritative).
    """
    index = {(event.trace_id, event.span_id): position for position, event in enumerate(events)}
    reported_below: set[int] = set()
    for event in events:
        if not event.usage:
            continue
        seen: set[int] = set()
        parent = event.parent_span_id
        while parent is not None:
            position = index.get((event.trace_id, parent))
            if position is None or position in seen:
                break
            seen.add(position)
            reported_below.add(position)
            parent = events[position].parent_span_id
    return [
        replace(event, kind="model")
        if position in inferred and event.usage and position not in reported_below
        else event
        for position, event in enumerate(events)
    ]
