"""``tine import --format otel-logs``: OTLP log records as a run.

The agent CLIs' richest telemetry travels as OpenTelemetry *logs*, not spans:
Claude Code's ``api_request`` events, Codex's ``sse_event``, Gemini CLI's
``api_response`` -- each one model call with its model and token usage. An
OTLP/JSON logs export (``resourceLogs`` -> ``scopeLogs`` -> ``logRecords``, or
the collector file exporter's one document per line) imports here: every
record a dialect in :mod:`opentine.trace._otel_dialects` recognizes becomes an
event, in time order, chained per session; everything else (configuration,
counters, lifecycle) is skipped.

Gemini CLI reports one call twice -- ``gemini_cli.api_response`` and the
semconv ``gen_ai.client.inference.operation.details`` -- so the semconv record
is used only when no ``api_response`` is present, never billed on top of it.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from opentine.trace._import_helpers import dictionary, first, integer, timestamp
from opentine.trace._otel_dialects import log_fields
from opentine.trace._otel_usage import otel_usage
from opentine.trace._otel_values import any_value
from opentine.trace._otel_values import attributes as decoded_attributes
from opentine.trace._provider_alias import canonical_provider
from opentine.trace._transcript_common import MAX_EVENTS, Chain
from opentine.trace.schema import TraceEvent

GEMINI_DETAILS = "gen_ai.client.inference.operation.details"
#: Raw log records read; counters and lifecycle noise outnumber the calls, so
#: this sits a few times above the event cap rather than at it.
_MAX_RECORDS = 400_000
_SESSION_KEYS = ("session.id", "conversation.id", "gen_ai.conversation.id", "prompt_id")


def log_records(source: Any) -> Iterator[dict[str, Any]]:
    """Every log record in an OTLP/JSON document, a list of them, or bare records."""
    seen = 0
    for document in source if isinstance(source, list) else [source]:
        if not isinstance(document, dict):
            continue
        resources = first(document, "resourceLogs", "resource_logs")
        if not isinstance(resources, list):
            if "logRecords" in document or "log_records" in document:
                resources = [{"scopeLogs": [document]}]
            elif any(key in document for key in ("body", "eventName", "attributes")):
                resources = [{"scopeLogs": [{"logRecords": [document]}]}]
            else:
                continue
        for resource in resources:
            scopes = first(dictionary(resource), "scopeLogs", "scope_logs", default=[])
            for scope in scopes if isinstance(scopes, list) else []:
                records = first(dictionary(scope), "logRecords", "log_records", default=[])
                for record in records if isinstance(records, list) else []:
                    seen += 1
                    if seen > _MAX_RECORDS:
                        raise ValueError("trace import exceeds maximum input-record count")
                    if isinstance(record, dict):
                        yield record


def _name(record: dict[str, Any], attributes: dict[str, Any]) -> str:
    for candidate in (record.get("eventName"), attributes.get("event.name")):
        if isinstance(candidate, str) and candidate:
            return candidate
    try:
        body = any_value(record.get("body"))
    except (RecursionError, ValueError):
        body = None
    return body if isinstance(body, str) and len(body) < 128 else ""


def _when(record: dict[str, Any], attributes: dict[str, Any]) -> float:
    nanos = integer(first(record, "timeUnixNano", "observedTimeUnixNano", default=0))
    if nanos:
        return nanos / 1_000_000_000
    return timestamp(attributes.get("event.timestamp") or 0)


def otel_log_events(source: Any) -> list[TraceEvent]:
    # One pass, counted as it goes: a file of a million records each naming its
    # own session used to be decoded, mapped and chained in full -- gigabytes --
    # before the event cap refused it (final security pass, #6).
    rows: list[tuple[float, str, dict[str, Any]]] = []
    details: list[tuple[float, str, dict[str, Any]]] = []
    has_gemini_responses = False
    for record in log_records(source):
        try:
            attributes = decoded_attributes(record)
        except (AttributeError, RecursionError, TypeError, ValueError):
            continue
        row = _row(record, attributes)
        if row is None:
            continue
        name, when, session, fields = row
        if name == "gemini_cli.api_response" and not has_gemini_responses:
            has_gemini_responses = True
            details.clear()  # the semconv duplicates are never used now
        if name != GEMINI_DETAILS:
            rows.append((when, session, fields))
        elif not has_gemini_responses:
            details.append((when, session, fields))
        if len(rows) + len(details) > MAX_EVENTS:
            raise ValueError("trace import exceeds maximum event count")
    rows.extend(details)
    rows.sort(key=lambda row: row[0])
    chains: dict[str, Chain] = {}
    for when, session, fields in rows:
        chain = chains.setdefault(session, Chain(session))
        kind = fields.pop("kind")
        fields["provider"] = canonical_provider(fields.get("provider") or "")
        chain.add(kind, when, "", **fields)
    events = [event for chain in chains.values() for event in chain.events]
    if len(events) > MAX_EVENTS:
        raise ValueError("trace import exceeds maximum event count")
    return events


def _row(
    record: dict[str, Any], attributes: dict[str, Any]
) -> tuple[str, float, str, dict[str, Any]] | None:
    """One record as ``(name, when, session, fields)``, or ``None`` if no step."""
    name = _name(record, attributes)
    try:
        if name == GEMINI_DETAILS:
            fields: dict[str, Any] | None = _semconv_details(attributes)
            dialect = "gen_ai"
        else:
            mapped = log_fields(name, attributes)
            if mapped is None:
                return None
            dialect, fields = mapped
    except (AttributeError, TypeError, ValueError):
        return None  # a well-formed record with an unexpected field type: skipped
    session = first(attributes, *_SESSION_KEYS, default="") or record.get("traceId") or dialect
    fields["attributes"] = {**dictionary(fields.get("attributes")), "otel.event.name": name}
    return name, _when(record, attributes), str(session)[:256], fields


def _semconv_details(attributes: dict[str, Any]) -> dict[str, Any]:
    usage, _ = otel_usage(dict(attributes))
    return {
        "kind": "model",
        "model": str(
            attributes.get("gen_ai.response.model") or attributes.get("gen_ai.request.model") or ""
        ),
        "provider": str(first(attributes, "gen_ai.provider.name", "gen_ai.system", default="")),
        "usage": usage,
    }


def looks_like_logs(document: Any) -> bool:
    items: Iterable[Any] = document if isinstance(document, list) else [document]
    return any(
        isinstance(item, dict) and ("resourceLogs" in item or "resource_logs" in item)
        for item in items
    )


__all__ = ["log_records", "looks_like_logs", "otel_log_events"]
