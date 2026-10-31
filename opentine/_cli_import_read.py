"""Reading the ``tine import`` SOURCE and routing it to an importer.

Split out of :mod:`opentine._cli_import` so that module stays under the
architecture gate's per-module line budget; the rules are unchanged. Nothing
here decides *what* an event means -- every format is parsed by the tested
importers in :mod:`opentine.trace.importers`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from opentine.trace._import_detect import TRANSCRIPT_IMPORTERS, detect_format
from opentine.trace._import_guard import bounded_lines, bounded_read, shape_checked
from opentine.trace._otel_log_import import looks_like_logs, otel_log_events
from opentine.trace.importers import (
    MAX_JSONL_LINE_BYTES,
    MAX_TRACE_IMPORT_BYTES,
    framework_events,
    jsonl_events,
    otel_genai_events,
)
from opentine.trace.schema import TraceEvent

STDIN = "-"


def _read_text(source: str) -> str:
    """Read the whole source, refusing more than one importer payload's worth.

    Bounded by reading, never by ``st_size``: a pipe, FIFO or device reports 0
    there and was then read whole. The structure scan runs on the raw bytes
    before anything is parsed (see :mod:`opentine.trace._import_guard`).
    """
    if source == STDIN:
        # .buffer for a real pipe; a text stream (a redirect, or a host that
        # substituted stdin) is read as text instead of raising AttributeError.
        data = bounded_read(getattr(sys.stdin, "buffer", sys.stdin), MAX_TRACE_IMPORT_BYTES)
    else:
        with Path(source).open("rb") as handle:
            data = bounded_read(handle, MAX_TRACE_IMPORT_BYTES)
    shape_checked(data)
    return data.decode("utf-8", "replace") if isinstance(data, bytes) else data


def _records(text: str) -> list:
    """Decode a JSON array, a single JSON object, or one JSON object per line.

    Whole-document parsing is tried first, so a pretty-printed array spanning
    many lines is not mistaken for JSONL; JSONL only reaches the per-line path
    because the concatenation is not itself valid JSON.
    """
    try:
        decoded = json.loads(text)
    except ValueError:
        pass
    else:
        return decoded if isinstance(decoded, list) else [decoded]
    records = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        # The decoder counts lines within the fragment it was handed, so on its
        # own it reports "line 1" for every bad record in the file.
        except ValueError as exc:
            raise ValueError(f"line {number} is not valid JSON: {exc}") from exc
    return records


def read_events(source: str, source_format: str) -> list[TraceEvent]:
    """Route *source* to the importer named by *source_format*."""
    return detect_and_read(source, source_format)[1]


def detect_and_read(
    source: str, source_format: str, adapter: str | None = None
) -> tuple[str, list[TraceEvent]]:
    """``(format, events)``: *source* through its importer, detecting ``auto``."""
    if adapter:  # an AdapterSpec, run under the core caps (never stdin)
        from opentine.harnesses._adapter_spec import resolve, run_adapter

        if source == STDIN:
            raise ValueError("--adapter reads a file path, not stdin")
        return f"adapter:{adapter}", run_adapter(resolve(adapter), source)
    if source_format == "jsonl":
        # The JSONL importer does its own bounded, streaming read of a path;
        # stdin gets the same per-line bound instead of whole-line buffering.
        if source != STDIN:
            return source_format, jsonl_events(source)
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        return source_format, jsonl_events(
            bounded_lines(
                stream, line_limit=MAX_JSONL_LINE_BYTES, total_limit=MAX_TRACE_IMPORT_BYTES
            )
        )
    if source != STDIN and source_format in ("auto", "opencode-session"):
        from opentine.trace._opencode_db import looks_like_sqlite, split_source

        if source_format == "opencode-session" or looks_like_sqlite(split_source(source)[0]):
            return "opencode-session", TRANSCRIPT_IMPORTERS["opencode-session"](source)
    if source_format == "opencode-session":
        raise ValueError("opencode-session imports read an opencode.db path, not stdin")
    if source_format == "auto" and source != STDIN and _is_entire_repo(source):
        return "entire", TRANSCRIPT_IMPORTERS["entire"](source)
    if source_format in TRANSCRIPT_IMPORTERS and source != STDIN:
        # Transcripts are read line by line from a path, each line bounded.
        return source_format, TRANSCRIPT_IMPORTERS[source_format](source)
    text = _read_text(source)
    if source_format == "auto":
        source_format = detect_format(text)
        if source_format in TRANSCRIPT_IMPORTERS and source != STDIN:
            # From the path, as an explicit --format does: a Claude Code
            # session's subagents/ files are found beside it (final pass 3, #4).
            return source_format, TRANSCRIPT_IMPORTERS[source_format](source)
        if source_format == "jsonl":
            return source_format, jsonl_events(text.splitlines())
    if source_format in TRANSCRIPT_IMPORTERS:
        return source_format, TRANSCRIPT_IMPORTERS[source_format](text.splitlines())
    if source_format in ("otel-json", "otel-logs"):
        documents = _documents(text)
        if source_format == "otel-logs" or (
            looks_like_logs(documents) and not _has_spans(documents)
        ):
            return "otel-logs", otel_log_events(documents)
        return source_format, otel_genai_events(documents)
    if source_format == "otel-spans":
        return source_format, otel_genai_events(_records(text))
    return source_format, framework_events(_records(text), source_format)


def _is_entire_repo(source: str) -> bool:
    """A directory SOURCE (optionally ``::checkpoint``) is read as an Entire repo."""
    from opentine.trace._import_entire import split_source

    try:
        return split_source(source)[0].is_dir()
    except ValueError:
        return False


def _documents(text: str) -> object:
    """One OTLP/JSON document, or the collector file exporter's one per line."""
    try:
        return json.loads(text)
    except ValueError:
        return _records(text)


def _has_spans(documents: object) -> bool:
    items = documents if isinstance(documents, list) else [documents]
    return any(
        isinstance(item, dict) and ("resourceSpans" in item or "resource_spans" in item)
        for item in items
    )
