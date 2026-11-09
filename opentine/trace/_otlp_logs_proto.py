"""OTLP protobuf logs into the OTLP/JSON shape the log importer reads (0.48).

:func:`decode_logs` turns an ``ExportLogsServiceRequest`` (the body of a
``POST /v1/logs`` with ``Content-Type: application/x-protobuf``, a gRPC
``LogsService/Export`` message, or a file of one) into the dict an OTLP/JSON
exporter would have sent, so :func:`opentine.trace._otel_log_import.otel_log_events`
reads both unchanged. Field numbers follow opentelemetry-proto ``logs/v1``;
the shared readers, caps and failure rules are those of
:mod:`opentine.trace._otlp_proto`.
"""

from __future__ import annotations

from typing import Any

from opentine.trace._otlp_proto import _Reader
from opentine.trace._protobuf_wire import LEN, WireError

_RECORD_TIMES = {1: "timeUnixNano", 11: "observedTimeUnixNano"}
_RECORD_IDS = {9: "traceId", 10: "spanId"}


class _LogReader(_Reader):
    def record(self, raw: int | bytes, depth: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for number, wire, value in self.message(raw, depth):
            if number in _RECORD_TIMES:
                out[_RECORD_TIMES[number]] = str(self.number(value))
            elif number == 2:
                out["severityNumber"] = self.number(value)
            elif number == 3:
                out["severityText"] = self.text(value)
            elif number == 5:
                out["body"] = self.any_value(value, depth + 1)
            elif number == 6:
                out.setdefault("attributes", []).append(self.key_value(value, depth + 1))
            elif number == 7:
                out["droppedAttributesCount"] = self.number(value)
            elif number == 8:
                out["flags"] = self.number(value)
            elif number in _RECORD_IDS:
                if wire != LEN:
                    raise WireError("log record id field is not bytes")
                out[_RECORD_IDS[number]] = bytes(value).hex()  # type: ignore[arg-type]
            elif number == 12:
                out["eventName"] = self.text(value)
        return out

    def scope_logs(self, raw: int | bytes, depth: int) -> dict[str, Any]:
        out: dict[str, Any] = {"logRecords": []}
        for number, _, value in self.message(raw, depth):
            if number == 1:
                names = {1: "name", 2: "version", 3: "attributes"}
                out["scope"] = self.attributed(value, depth + 1, names)
            elif number == 2:
                out["logRecords"].append(self.record(value, depth + 1))
            elif number == 3:
                out["schemaUrl"] = self.text(value)
        return out

    def resource_logs(self, raw: int | bytes, depth: int) -> dict[str, Any]:
        out: dict[str, Any] = {"scopeLogs": []}
        for number, _, value in self.message(raw, depth):
            if number == 1:
                out["resource"] = self.attributed(value, depth + 1, {1: "attributes"})
            elif number == 2:
                out["scopeLogs"].append(self.scope_logs(value, depth + 1))
            elif number == 3:
                out["schemaUrl"] = self.text(value)
        return out


def decode_logs(data: bytes) -> dict[str, Any]:
    """An ``ExportLogsServiceRequest`` as an OTLP/JSON document."""
    reader = _LogReader()
    try:
        groups = [
            reader.resource_logs(value, 1)
            for number, _, value in reader.message(bytes(data), 0)
            if number == 1
        ]
    except RecursionError as exc:
        raise WireError("message nests too deeply") from exc
    return {"resourceLogs": groups}


__all__ = ["WireError", "decode_logs"]
