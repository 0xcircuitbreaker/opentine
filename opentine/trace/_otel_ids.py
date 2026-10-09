"""OTLP-shaped trace and span ids for OpenTine's own ids, and the way back.

OTLP requires a ``traceId`` of 16 bytes and a ``spanId`` of 8 (32 and 16 hex
characters in OTLP/JSON); a spec-strict collector rejects the whole batch
otherwise. A native run's ids are a 64-hex run digest (or any string a supplied
artifact chose) and 64-hex step digests, so export derives a conforming id from
each -- deterministically, so every span of a run lands in one trace and parent
and link references still meet -- and carries the original in an ``opentine.*``
attribute. An id that already has the OTLP shape (one an import brought in) is
kept as it is, so an imported trace re-exports byte-identically. The importer
reads the originals back and drops the attributes, so a native run that goes out
and comes back keeps every id it had.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from opentine.trace._import_helpers import first, link_span_ids, optional_string

RUN_ID_ATTRIBUTE = "opentine.run_id"
STEP_ID_ATTRIBUTE = "opentine.step_id"
PARENT_ID_ATTRIBUTE = "opentine.parent_step_id"
CAUSAL_IDS_ATTRIBUTE = "opentine.causal_step_ids"
_TRACE_SHAPE = re.compile(r"[0-9a-f]{32}")
_SPAN_SHAPE = re.compile(r"[0-9a-f]{16}")


def _shaped(value: str, shape: re.Pattern[str], width: int, domain: bytes) -> str:
    if shape.fullmatch(value) and value.strip("0"):  # all-zero ids are invalid in OTLP
        return value
    digest = hashlib.sha256(domain + b"\0" + value.encode("utf-8", "surrogatepass"))
    return digest.hexdigest()[:width]


def otlp_trace_id(value: Any) -> str:
    return _shaped(str(value), _TRACE_SHAPE, 32, b"opentine.otlp.trace")


def otlp_span_id(value: Any) -> str:
    return _shaped(str(value), _SPAN_SHAPE, 16, b"opentine.otlp.span")


def export_ids(event: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """The OTLP id fields for *event*, and the attributes naming any id it replaced."""
    trace, span = str(event.trace_id), str(event.span_id)
    ids: dict[str, Any] = {"traceId": otlp_trace_id(trace), "spanId": otlp_span_id(span)}
    originals: dict[str, Any] = {}
    if ids["traceId"] != trace:
        originals[RUN_ID_ATTRIBUTE] = trace
    if ids["spanId"] != span:
        originals[STEP_ID_ATTRIBUTE] = span
    if event.parent_span_id:
        parent = str(event.parent_span_id)
        ids["parentSpanId"] = otlp_span_id(parent)
        if ids["parentSpanId"] != parent:
            originals[PARENT_ID_ATTRIBUTE] = parent
    causal = [str(value) for value in event.causal_span_ids]
    ids["links"] = [otlp_span_id(value) for value in causal]
    if ids["links"] != causal:
        originals[CAUSAL_IDS_ATTRIBUTE] = causal
    return ids, originals


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def imported_ids(
    span: dict[str, Any], attributes: dict[str, Any], position: int
) -> tuple[str, str, str | None, tuple[str, ...]]:
    """(trace, span, parent, causal) ids for an imported span, originals first.

    Pops the ``opentine.*`` id attributes, which name ids an export replaced.
    """
    trace = _text(attributes.pop(RUN_ID_ATTRIBUTE, None))
    step = _text(attributes.pop(STEP_ID_ATTRIBUTE, None))
    parent = _text(attributes.pop(PARENT_ID_ATTRIBUTE, None))
    causal = attributes.pop(CAUSAL_IDS_ATTRIBUTE, None)
    if not isinstance(causal, list) or not all(_text(value) for value in causal):
        causal = None
    return (
        trace or str(first(span, "traceId", "trace_id", default="")),
        step or str(first(span, "spanId", "span_id", default=position)),
        parent or optional_string(first(span, "parentSpanId", "parent_span_id")),
        tuple(causal) if causal is not None else link_span_ids(span),
    )
