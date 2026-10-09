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

from opentine.trace._import_guard import bounded_lines, bounded_read, shape_checked
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
    if source_format == "jsonl":
        # The JSONL importer does its own bounded, streaming read of a path;
        # stdin gets the same per-line bound instead of whole-line buffering.
        if source != STDIN:
            return jsonl_events(source)
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        return jsonl_events(
            bounded_lines(
                stream, line_limit=MAX_JSONL_LINE_BYTES, total_limit=MAX_TRACE_IMPORT_BYTES
            )
        )
    text = _read_text(source)
    if source_format == "otel-json":
        return otel_genai_events(json.loads(text))
    if source_format == "otel-spans":
        return otel_genai_events(_records(text))
    return framework_events(_records(text), source_format)
