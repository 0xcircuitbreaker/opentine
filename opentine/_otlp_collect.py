"""Buffer live OTLP spans and log records into runs for ``tine serve --otlp``.

Nothing here parses OTLP: spans are read by
:func:`opentine.trace.otel_genai_events` and log records by
:func:`opentine.trace._otel_log_import.otel_log_events`, exactly as ``tine
import`` reads a file. This module only groups what arrives -- spans by
``traceId``, log records by session (or trace) -- and decides when a group is a
finished run: its root span arrived (a span is exported once it has ended), it
went quiet for the idle timeout, or the receiver is shutting down.

A finished group goes through the ``tine import`` write path (billing
distrusted, unpriced steps marked, recorded in a scratch repository) after
every free-form value is redacted, and the resulting run is handed to *save*.
"""

from __future__ import annotations

import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from opentine.core import Run
from opentine.redaction import redact_text, redact_value
from opentine.trace._import_helpers import dictionary, first, otel_spans
from opentine.trace._otel_log_import import _SESSION_KEYS, log_records, otel_log_events
from opentine.trace._otel_values import attributes as decoded_attributes
from opentine.trace.importers import MAX_TRACE_EVENTS, otel_genai_events
from opentine.trace.schema import TraceEvent

#: Spans plus log records held across every open group; past it, all flush.
MAX_PENDING = 200_000
SPANS, LOGS = "otel-json", "otel-logs"


def _redacted(event: TraceEvent) -> TraceEvent:
    return replace(
        event,
        actor=redact_text(event.actor),
        inputs=redact_value(event.inputs),
        outputs=redact_value(event.outputs),
        attributes=redact_value(event.attributes),
    )


def write_run(events: list[TraceEvent], source_format: str, save: Callable[[Run], Any]) -> Any:
    """Record *events* like ``tine import`` does and pass the run to *save*."""
    from opentine._import_billing import distrust_source_billing, mark_unpriced
    from opentine._import_write import record
    from opentine.repo import Repo

    events = mark_unpriced(distrust_source_billing([_redacted(item) for item in events]))
    with tempfile.TemporaryDirectory(prefix="tine-otlp-") as scratch:
        repo = Repo.init(Path(scratch) / "otlp")
        run = repo.load_run(record(repo, events, "heads/main", None, source_format))
        return save(run)


def _log_key(record: dict[str, Any]) -> str:
    try:
        attributes = decoded_attributes(record)
    except (AttributeError, RecursionError, TypeError, ValueError):
        attributes = {}
    for key in _SESSION_KEYS:
        if attributes.get(key):
            return f"session:{attributes[key]}"
    trace = first(record, "traceId", "trace_id", default="")
    return f"trace:{trace}" if trace else "logs"


class OtlpCollector:
    """Thread-safe groups of pending spans/log records, flushed into runs."""

    def __init__(
        self,
        save: Callable[[Run], Any],
        *,
        idle: float = 30.0,
        report: Callable[[str], Any] = lambda message: None,
    ) -> None:
        self._save, self.idle, self._report = save, idle, report
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self._seen: dict[tuple[str, str], float] = {}
        self.saved: list[Any] = []

    def pending(self) -> int:
        with self._lock:
            return sum(len(items) for items in self._groups.values())

    def _add(self, key: tuple[str, str], item: dict[str, Any]) -> None:
        self._groups.setdefault(key, []).append(item)
        self._seen[key] = time.monotonic()

    def _take(self, keys: list[tuple[str, str]]) -> list[tuple[str, list[dict[str, Any]]]]:
        taken = []
        for key in dict.fromkeys(keys):
            items = self._groups.pop(key, None)
            self._seen.pop(key, None)
            if items:
                taken.append((key[0], items))
        return taken

    def _overflow(self, ready: list[tuple[str, str]]) -> list[tuple[str, str]]:
        total = sum(len(items) for items in self._groups.values())
        if total > MAX_PENDING:
            return list(self._groups)
        return ready + [
            key for key, items in self._groups.items() if len(items) >= MAX_TRACE_EVENTS
        ]

    def add_spans(self, document: Any) -> int:
        """Buffer a ``/v1/traces`` body; the count of spans rejected (no traceId)."""
        rejected, ready = 0, []
        with self._lock:
            for span in otel_spans(document):
                trace = str(first(span, "traceId", "trace_id", default="") or "")
                if not trace:
                    rejected += 1
                    continue
                self._add((SPANS, trace), span)
                if not first(span, "parentSpanId", "parent_span_id", default=""):
                    ready.append((SPANS, trace))  # the root ended: its run is done
            batches = self._take(self._overflow(ready))
        self._write(batches)
        return rejected

    def add_logs(self, document: Any) -> int:
        """Buffer a ``/v1/logs`` body, each record kept with its resource."""
        with self._lock:
            for resource in _resources(document):
                for record in log_records({"resourceLogs": [resource]}):
                    wrapped = {**resource, "scopeLogs": [{"logRecords": [record]}]}
                    self._add((LOGS, _log_key(record)), {"resourceLogs": [wrapped]})
            batches = self._take(self._overflow([]))
        self._write(batches)
        return 0

    def flush_idle(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            stale = [key for key, seen in self._seen.items() if now - seen >= self.idle]
            batches = self._take(stale)
        self._write(batches)

    def flush_all(self) -> None:
        with self._lock:
            batches = self._take(list(self._groups))
        self._write(batches)

    def _write(self, batches: list[tuple[str, list[dict[str, Any]]]]) -> None:
        for source_format, items in batches:
            try:
                events = otel_genai_events(items) if source_format == SPANS else None
                events = otel_log_events(items) if events is None else events
                if not events:
                    continue
                with self._write_lock:
                    self.saved.append(write_run(events, source_format, self._save))
            except (OSError, RecursionError, ValueError) as exc:
                self._report(f"OTLP batch dropped: {redact_text(str(exc))}")


def _resources(document: Any) -> list[dict[str, Any]]:
    resources = first(dictionary(document), "resourceLogs", "resource_logs", default=None)
    if isinstance(resources, list):
        return [item for item in resources if isinstance(item, dict)]
    return [{"scopeLogs": [document]}] if isinstance(document, dict) else []


__all__ = ["MAX_PENDING", "OtlpCollector", "write_run"]
