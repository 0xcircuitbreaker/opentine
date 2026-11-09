"""Vendor I/O (0.46): Langfuse, Arize Phoenix, Braintrust and LangSmith files.

``tine export RUN --format langfuse|phoenix|braintrust|langsmith`` writes the
JSON body the vendor's public ingestion API takes; ``tine import FILE --format
<same>`` reads that body back, or the vendor's own export of the same records.
Everything is file based and offline: no vendor API is called, so a file can be
reviewed (and redacted) before anyone uploads it.

Both directions go through one neutral span (:func:`from_otlp`/:func:`to_otlp`)
and the OTLP/JSON exporter and importer, so a vendor file imports with the same
kinds, usage and content rules as ``--format otel-json``. Each vendor module
(``_vendor_langfuse`` ...) only reshapes neutral spans.

Neutral span keys: ``trace``, ``span``, ``parent`` (vendor ids, any string),
``name``, ``kind`` (``model``/``tool``/``step``), ``start``/``end`` (Unix
nanoseconds), ``input``, ``output``, ``model``, ``tokens_in``, ``tokens_out``,
``error`` (text or ``None``) and ``evals``: ``[{name, score, label,
explanation}]``, the fields of an OTel ``gen_ai.evaluation.result`` event.
Evaluations ride on the OTLP span both as those events and as the
:data:`EVAL_ATTRIBUTE` JSON attribute (the importer keeps attributes, not
events), so a vendor score survives import -> export.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from datetime import UTC, datetime
from typing import Any

from opentine.trace import _genai_semconv as semconv
from opentine.trace._otel_values import attributes as span_attributes
from opentine.trace._otel_values import encode_any_value

VENDOR_FORMATS = ("langfuse", "phoenix", "braintrust", "langsmith")
EVAL_EVENT = "gen_ai.evaluation.result"
EVAL_ATTRIBUTE = "opentine.evaluation.results"
VENDOR_ID = "opentine.vendor.span_id"
MAX_SPANS = 100_000
_KINDS = {"model": "model", "tool": "tool"}


def iso(nanos: int) -> str:
    """Unix nanoseconds -> RFC 3339 UTC with microseconds (every vendor reads it)."""
    stamp = datetime.fromtimestamp(nanos / 1e9, UTC).isoformat(timespec="microseconds")
    return stamp.replace("+00:00", "Z")


def nanos(value: Any) -> int:
    """An RFC 3339 string, epoch seconds or nanoseconds -> Unix nanoseconds (0 if unknown)."""
    if isinstance(value, bool) or value is None:
        return 0
    if isinstance(value, (int, float)):
        if value != value or not 0 < value < 1e19:  # NaN, infinite, negative, overflowing
            return 0
        scale = 1 if value >= 1e17 else 1e3 if value >= 1e14 else 1e6 if value >= 1e11 else 1e9
        return round(value * scale / 1000) * 1000 if scale > 1 else int(value)  # ns, to the us
    if isinstance(value, str) and value:
        if value.isdigit():
            return nanos(int(value))
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return 0
        parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        return round(parsed.timestamp() * 1e6) * 1000
    return 0


def hex_id(value: Any, size: int) -> str:
    """A vendor id as an OTLP hex id: kept when it already is one, else hashed."""
    text = str(value or "")
    if len(text) == size and all(c in "0123456789abcdef" for c in text):
        return text
    return hashlib.sha256(text.encode()).hexdigest()[:size]


def text_or_json(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)


def maybe_json(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in "{[":
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def unwrap(payload: Any) -> Any:
    """OpenTine's ``{"value": x}`` wrapper (what :func:`to_otlp` adds) -> ``x``."""
    if isinstance(payload, dict) and list(payload) == ["value"]:
        return payload["value"]
    return payload


def wrap(payload: Any) -> Any:
    return payload if isinstance(payload, dict) or payload is None else {"value": payload}


def evaluation(name: Any, score: Any = None, label: Any = None, why: Any = None) -> dict:
    number = score if isinstance(score, (int, float)) and not isinstance(score, bool) else None
    return {"name": str(name or "score"), "score": number,
            "label": None if label is None else str(label),
            "explanation": None if why is None else str(why)}  # fmt: skip


def _number(value: Any) -> int | None:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def from_otlp(document: dict[str, Any]) -> list[dict[str, Any]]:
    """The neutral spans of an OTLP/JSON document (what ``to_otel_genai_document`` writes)."""
    spans: list[dict[str, Any]] = []
    for resource in document.get("resourceSpans") or []:
        for scope in resource.get("scopeSpans") or []:
            for span in scope.get("spans") or []:
                attrs = span_attributes(span)
                operation = str(attrs.get(semconv.OPERATION_NAME) or span.get("name") or "")
                kind = str(attrs.get(semconv.KIND_ATTRIBUTE) or "")
                if not kind:
                    from opentine.trace._otel_usage import otel_kind

                    kind = otel_kind(operation)
                evals = attrs.get(EVAL_ATTRIBUTE)
                status = span.get("status") or {}
                error = status.get("message") or "error" if status.get("code") in (
                    2, "STATUS_CODE_ERROR") else None  # fmt: skip
                spans.append({
                    "trace": span.get("traceId", ""), "span": span.get("spanId", ""),
                    "parent": span.get("parentSpanId") or None, "name": operation,
                    "kind": _KINDS.get(kind, "step"),
                    "start": int(span.get("startTimeUnixNano") or 0),
                    "end": int(span.get("endTimeUnixNano") or 0),
                    "input": unwrap(attrs.get(semconv.PROMPT)),
                    "output": unwrap(attrs.get(semconv.COMPLETION)),
                    "model": attrs.get(semconv.RESPONSE_MODEL) or attrs.get(semconv.REQUEST_MODEL),
                    "tokens_in": _number(attrs.get(semconv.INPUT_TOKENS)),
                    "tokens_out": _number(attrs.get(semconv.OUTPUT_TOKENS)),
                    "error": error,
                    "evals": json.loads(evals) if isinstance(evals, str) else [],
                })  # fmt: skip
    return spans


def _otlp_span(span: dict[str, Any]) -> dict[str, Any]:
    attrs: dict[str, Any] = {semconv.OPERATION_NAME: span["name"] or span["kind"]}
    if span["kind"] in _KINDS:  # a vendor's chain/task span: kind from its name
        attrs[semconv.KIND_ATTRIBUTE] = span["kind"]
    attrs[VENDOR_ID] = str(span["span"])
    for key, value in ((semconv.PROMPT, wrap(span.get("input"))),
                       (semconv.COMPLETION, wrap(span.get("output"))),
                       (semconv.RESPONSE_MODEL, span.get("model")),
                       (semconv.INPUT_TOKENS, _number(span.get("tokens_in"))),
                       (semconv.OUTPUT_TOKENS, _number(span.get("tokens_out")))):  # fmt: skip
        if value is not None:
            attrs[key] = value
    evals = span.get("evals") or []
    if evals:
        attrs[EVAL_ATTRIBUTE] = json.dumps(evals, sort_keys=True)
    out: dict[str, Any] = {
        "name": str(span["name"] or span["kind"]), "traceId": hex_id(span["trace"], 32),
        "spanId": hex_id(span["span"], 16), "kind": "SPAN_KIND_INTERNAL",
        "startTimeUnixNano": str(span["start"]),
        "endTimeUnixNano": str(max(span["end"], span["start"])),
        "attributes": [{"key": k, "value": encode_any_value(v)} for k, v in attrs.items()],
        "events": [eval_event(item, span["end"] or span["start"]) for item in evals],
    }  # fmt: skip
    if span.get("parent"):
        out["parentSpanId"] = hex_id(span["parent"], 16)
    if span.get("error"):
        out["status"] = {"code": "STATUS_CODE_ERROR", "message": str(span["error"])}
    return out


def eval_event(item: dict[str, Any], at: int) -> dict[str, Any]:
    """One ``gen_ai.evaluation.result`` span event (OTel GenAI semconv)."""
    fields = {"gen_ai.evaluation.name": item.get("name"),
              "gen_ai.evaluation.score.value": item.get("score"),
              "gen_ai.evaluation.score.label": item.get("label"),
              "gen_ai.evaluation.explanation": item.get("explanation")}  # fmt: skip
    attrs = [{"key": k, "value": encode_any_value(v)} for k, v in fields.items() if v is not None]
    return {"name": EVAL_EVENT, "timeUnixNano": str(at), "attributes": attrs}


def to_otlp(spans: list[dict[str, Any]]) -> dict[str, Any]:
    if len(spans) > MAX_SPANS:
        raise ValueError("vendor import exceeds the maximum span count")
    ordered = sorted(spans, key=lambda s: (s["start"], str(s["span"])))
    scope = {"scope": {"name": "opentine.vendor"}, "spans": [_otlp_span(s) for s in ordered]}
    return {"resourceSpans": [{"resource": {"attributes": []}, "scopeSpans": [scope]}]}


def _module(fmt: str) -> Any:
    if fmt not in VENDOR_FORMATS:
        raise ValueError(f"unknown vendor format {fmt!r}")
    return importlib.import_module(f"opentine._vendor_{fmt}")


def export_document(fmt: str, run: Any) -> dict[str, Any]:
    """The run as *fmt*'s ingestion body (the caller redacts the run first)."""
    from opentine.trace.exporters import to_otel_genai_document

    return _module(fmt).export(from_otlp(to_otel_genai_document(run)))


def parse_document(fmt: str, text: str) -> list[dict[str, Any]]:
    """Neutral spans from *fmt*'s file: one JSON document, or JSON Lines."""
    try:
        document: Any = json.loads(text)
    except ValueError:
        document = [json.loads(line) for line in text.splitlines() if line.strip()]
    spans = _module(fmt).parse(document)
    if not spans:
        raise ValueError(f"no {fmt} spans found")
    return spans


def import_events(fmt: str, text: str) -> list[Any]:
    """``tine import --format <vendor>``: trace events; a malformed file is a ValueError."""
    from opentine.trace.importers import otel_genai_events

    try:
        return otel_genai_events(to_otlp(parse_document(fmt, text)))
    except (TypeError, AttributeError, KeyError, IndexError, OverflowError, RecursionError) as exc:
        raise ValueError(f"malformed {fmt} file: {type(exc).__name__}") from exc


def records(document: Any, *keys: str) -> list[dict[str, Any]]:
    """The record list under the first of *keys*, or *document* itself when a list."""
    if isinstance(document, dict):
        for key in keys:
            if isinstance(document.get(key), list):
                return [r for r in document[key] if isinstance(r, dict)]
        return [document]
    return [r for r in document if isinstance(r, dict)] if isinstance(document, list) else []


__all__ = ["EVAL_ATTRIBUTE", "EVAL_EVENT", "VENDOR_FORMATS", "eval_event", "evaluation",
           "export_document", "from_otlp", "import_events", "iso", "nanos", "parse_document",
           "records", "to_otlp"]  # fmt: skip
