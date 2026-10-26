"""Recognize what an import source is, for ``tine import --format auto``.

Plug-and-play import means not making the user name a format they may not know:
an OTLP export, an OpenTine JSONL trace, and the session logs of Claude Code,
Codex, Gemini CLI and Qwen Code each have a shape no other one shares. Only the
first records are looked at, and a source nothing matches is refused by name
rather than imported as whatever came closest.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from opentine._atif import atif_events
from opentine._atif_parse import is_atif
from opentine.trace._import_hermes import hermes_events, looks_like_hermes
from opentine.trace._transcript_claude import claude_transcript_events, looks_like_claude
from opentine.trace._transcript_codex import codex_session_events, looks_like_codex
from opentine.trace._transcript_gemini import gemini_session_events, looks_like_gemini
from opentine.trace._transcript_opencode import opencode_events
from opentine.trace._transcript_qwen import looks_like_qwen, qwen_session_events
from opentine.trace.schema import TraceEvent

TRANSCRIPT_IMPORTERS: dict[str, Callable[[Any], list[TraceEvent]]] = {
    "claude-code-transcript": claude_transcript_events,
    "codex-session": codex_session_events,
    "gemini-session": gemini_session_events,
    "qwen-session": qwen_session_events,
    "atif": atif_events,
    "opencode-session": opencode_events,  # a SQLite path only, never stdin text
    "hermes-trajectory": hermes_events,  # path or path::N; the last record by default
}
TRANSCRIPT_FORMATS = tuple(TRANSCRIPT_IMPORTERS)
_SNIFF_LINES = 64


def _first_records(text: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for line in text.splitlines()[:_SNIFF_LINES]:
        try:
            item = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(item, dict):
            found.append(item)
    return found


def _document_format(document: Any) -> str | None:
    items = document if isinstance(document, list) else [document]
    dicts = [item for item in items[:_SNIFF_LINES] if isinstance(item, dict)]
    if not dicts:
        return None
    if is_atif(document):
        return "atif"
    if any("resourceSpans" in item or "resource_spans" in item for item in dicts):
        return "otel-json"
    if any("resourceLogs" in item or "resource_logs" in item for item in dicts):
        return "otel-logs"
    if (
        isinstance(document, dict)
        and isinstance(document.get("messages"), list)
        and ("projectHash" in document)
    ):
        return "gemini-session"
    if any(("traceId" in item or "trace_id" in item) and "spanId" in item for item in dicts):
        return "otel-spans"
    if isinstance(document, dict) and isinstance(document.get("spans"), list):
        return "otel-json"
    return None


def detect_format(text: str) -> str:
    """The import format *text* is in, or a ``ValueError`` naming the choices."""
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        document = None
    found = _document_format(document) if document is not None else None
    if found:
        return found
    records = _first_records(text)
    checks = (
        ("otel-logs", lambda item: "resourceLogs" in item or "resource_logs" in item),
        ("otel-json", lambda item: "resourceSpans" in item or "resource_spans" in item),
        ("hermes-trajectory", looks_like_hermes),
        ("codex-session", looks_like_codex),
        ("qwen-session", looks_like_qwen),
        ("claude-code-transcript", looks_like_claude),
        ("gemini-session", looks_like_gemini),
        ("otel-spans", lambda item: "traceId" in item and "spanId" in item),
        ("jsonl", lambda item: "span_id" in item or ("kind" in item and "trace_id" in item)),
    )
    for name, check in checks:
        if any(check(item) for item in records):
            return name
    raise ValueError(
        "could not recognize the import format; pass --format "
        "(otel-json, otel-logs, otel-spans, jsonl, claude-code-transcript, "
        "codex-session, gemini-session, qwen-session, hermes-trajectory, or a framework name)"
    )


__all__ = ["TRANSCRIPT_FORMATS", "TRANSCRIPT_IMPORTERS", "detect_format"]
