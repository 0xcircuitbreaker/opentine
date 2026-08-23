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

from opentine.trace.importers import (
    MAX_TRACE_IMPORT_BYTES,
    framework_events,
    jsonl_events,
    otel_genai_events,
)
from opentine.trace.schema import TraceEvent

STDIN = "-"


def _read_text(source: str) -> str:
    """Read the whole source, refusing more than one importer payload's worth."""
    if source == STDIN:
        # .buffer for a real pipe; a text stream (a redirect, or a host that
        # substituted stdin) is read as text instead of raising AttributeError.
        data = getattr(sys.stdin, "buffer", sys.stdin).read(MAX_TRACE_IMPORT_BYTES + 1)
    else:
        path = Path(source)
        if path.stat().st_size > MAX_TRACE_IMPORT_BYTES:
            raise ValueError("trace import exceeds aggregate payload limit")
        data = path.read_bytes()
    if len(data) > MAX_TRACE_IMPORT_BYTES:
        raise ValueError("trace import exceeds aggregate payload limit")
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
        # The JSONL importer does its own bounded, streaming read of a path.
        return jsonl_events(sys.stdin if source == STDIN else source)
    text = _read_text(source)
    if source_format == "otel-json":
        return otel_genai_events(json.loads(text))
    if source_format == "otel-spans":
        return otel_genai_events(_records(text))
    return framework_events(_records(text), source_format)
