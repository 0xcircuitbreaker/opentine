"""OTLP/HTTP protobuf traces into the OTLP/JSON shape the span importer reads.

:func:`decode_traces` turns an ``ExportTraceServiceRequest`` (the body of a
``POST /v1/traces`` with ``Content-Type: application/x-protobuf``, or a file of
one) into the same dict an OTLP/JSON exporter would have sent: hex trace and
span ids, decimal-string nanosecond times, ``AnyValue`` objects. The GenAI
mapping is then :func:`opentine.trace.importers.otel_genai_events`, unchanged,
so protobuf and JSON exports of one trace import to the same run.

Field numbers follow opentelemetry-proto ``trace/v1`` and ``common/v1``.
Unknown fields are skipped, as protobuf requires; a field of the wrong wire type
is malformed. Every failure is a ``ValueError`` (see
:mod:`opentine.trace._protobuf_wire` for the caps).
"""

from __future__ import annotations

import base64
from typing import Any

from opentine.trace._protobuf_wire import (
    LEN,
    MAX_DEPTH,
    VARINT,
    Budget,
    WireError,
    double,
    fields,
    signed64,
)

_SPAN_BYTES = {1: "traceId", 2: "spanId", 4: "parentSpanId"}
_SPAN_TEXT = {3: "traceState", 5: "name"}
_SPAN_TIMES = {7: "startTimeUnixNano", 8: "endTimeUnixNano"}


class _Reader:
    def __init__(self) -> None:
        self.budget = Budget()

    def message(self, value: int | bytes, depth: int) -> list[tuple[int, int, int | bytes]]:
        if depth > MAX_DEPTH:
            raise WireError(f"message nesting exceeds {MAX_DEPTH}")
        if not isinstance(value, bytes):
            raise WireError("expected a length-delimited message")
        return fields(value, self.budget)

    @staticmethod
    def text(value: int | bytes) -> str:
        if not isinstance(value, bytes):
            raise WireError("expected a length-delimited string")
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WireError("string field is not UTF-8") from exc

    @staticmethod
    def number(value: int | bytes) -> int:
        if isinstance(value, bytes):
            raise WireError("expected a numeric field")
        return value

    def any_value(self, raw: int | bytes, depth: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for number, wire, value in self.message(raw, depth):
            if number == 1:
                out = {"stringValue": self.text(value)}
            elif number == 2 and wire == VARINT:
                out = {"boolValue": bool(value)}
            elif number == 3 and wire == VARINT:
                out = {"intValue": str(signed64(self.number(value)))}
            elif number == 4:
                out = {"doubleValue": double(self.number(value))}
            elif number == 5:
                items = [
                    self.any_value(v, depth + 2)
                    for n, _, v in self.message(value, depth + 1)
                    if n == 1
                ]
                out = {"arrayValue": {"values": items}}
            elif number == 6:
                pairs = [
                    self.key_value(v, depth + 2)
                    for n, _, v in self.message(value, depth + 1)
                    if n == 1
                ]
                out = {"kvlistValue": {"values": pairs}}
            elif number == 7 and wire == LEN:
                out = {"bytesValue": base64.b64encode(bytes(value)).decode()}  # type: ignore[arg-type]
        return out

    def key_value(self, raw: int | bytes, depth: int) -> dict[str, Any]:
        out: dict[str, Any] = {"key": "", "value": {}}
        for number, _, value in self.message(raw, depth):
            if number == 1:
                out["key"] = self.text(value)
            elif number == 2:
                out["value"] = self.any_value(value, depth + 1)
        return out

    def attributed(self, raw: int | bytes, depth: int, names: dict[int, str]) -> dict[str, Any]:
        """A Resource, InstrumentationScope, Event, Link or Status message."""
        out: dict[str, Any] = {}
        for number, wire, value in self.message(raw, depth):
            name = names.get(number)
            if name == "attributes":
                out.setdefault("attributes", []).append(self.key_value(value, depth + 1))
            elif name in ("traceId", "spanId"):
                out[name] = bytes(value).hex() if wire == LEN else ""  # type: ignore[arg-type]
            elif name == "timeUnixNano":
                out[name] = str(self.number(value))
            elif name == "code":
                out[name] = self.number(value)
            elif name is not None:
                out[name] = self.text(value)
        return out

    def span(self, raw: int | bytes, depth: int) -> dict[str, Any]:
        span: dict[str, Any] = {}
        for number, wire, value in self.message(raw, depth):
            if number in _SPAN_BYTES:
                if wire != LEN:
                    raise WireError("span id field is not bytes")
                span[_SPAN_BYTES[number]] = bytes(value).hex()  # type: ignore[arg-type]
            elif number in _SPAN_TEXT:
                span[_SPAN_TEXT[number]] = self.text(value)
            elif number == 6:
                span["kind"] = self.number(value)
            elif number in _SPAN_TIMES:
                span[_SPAN_TIMES[number]] = str(self.number(value))
            elif number == 9:
                span.setdefault("attributes", []).append(self.key_value(value, depth + 1))
            elif number == 11:
                names = {1: "timeUnixNano", 2: "name", 3: "attributes"}
                span.setdefault("events", []).append(self.attributed(value, depth + 1, names))
            elif number == 13:
                names = {1: "traceId", 2: "spanId", 3: "traceState", 4: "attributes"}
                span.setdefault("links", []).append(self.attributed(value, depth + 1, names))
            elif number == 15:
                span["status"] = self.attributed(value, depth + 1, {2: "message", 3: "code"})
        return span

    def scope_spans(self, raw: int | bytes, depth: int) -> dict[str, Any]:
        out: dict[str, Any] = {"spans": []}
        for number, _, value in self.message(raw, depth):
            if number == 1:
                names = {1: "name", 2: "version", 3: "attributes"}
                out["scope"] = self.attributed(value, depth + 1, names)
            elif number == 2:
                out["spans"].append(self.span(value, depth + 1))
            elif number == 3:
                out["schemaUrl"] = self.text(value)
        return out

    def resource_spans(self, raw: int | bytes, depth: int) -> dict[str, Any]:
        out: dict[str, Any] = {"scopeSpans": []}
        for number, _, value in self.message(raw, depth):
            if number == 1:
                out["resource"] = self.attributed(value, depth + 1, {1: "attributes"})
            elif number == 2:
                out["scopeSpans"].append(self.scope_spans(value, depth + 1))
            elif number == 3:
                out["schemaUrl"] = self.text(value)
        return out


def decode_traces(data: bytes) -> dict[str, Any]:
    """An ``ExportTraceServiceRequest`` as an OTLP/JSON document."""
    reader = _Reader()
    try:
        groups = [
            reader.resource_spans(value, 1)
            for number, _, value in reader.message(bytes(data), 0)
            if number == 1
        ]
    except RecursionError as exc:
        raise WireError("message nests too deeply") from exc
    return {"resourceSpans": groups}


__all__ = ["WireError", "decode_traces"]
