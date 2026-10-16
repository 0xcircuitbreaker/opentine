"""Import a Qwen Code session record (``~/.qwen/projects/<project>/chats/*.jsonl``).

Qwen Code appends ``{uuid, parentUuid, sessionId, timestamp, type: "user"|
"assistant"|"tool_result"|"system", message: {role, parts}, model?,
usageMetadata?, toolCallResult?}``: the Gemini content shape, with each API
response's ``usageMetadata`` verbatim (``promptTokenCount`` includes
``cachedContentTokenCount``; ``candidatesTokenCount`` excludes thoughts).
Qwen Code talks to several providers, so the provider is recorded only when
the model names one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine.trace._transcript_common import (
    SHAPE_ERRORS,
    Chain,
    gemini_usage,
    note_skipped,
    records,
)
from opentine.trace._transcript_gemini import _parts_text, _provider
from opentine.trace.schema import TraceEvent

QWEN_FORMAT = "qwen-session"


def qwen_session_events(source: str | Path | list[Any]) -> list[TraceEvent]:
    chain: Chain | None = None
    skipped = 0
    for record in records(source):
        if chain is None and isinstance(record.get("sessionId"), str):
            chain = Chain(record["sessionId"])
        if chain is None:
            continue
        try:
            _record(chain, record)
        except SHAPE_ERRORS:
            skipped += 1
    return note_skipped(chain.events, skipped) if chain else []


def _record(chain: Chain, record: dict[str, Any]) -> None:
    message = record.get("message") if isinstance(record.get("message"), dict) else {}
    parts = message.get("parts")
    kind, when, identifier = (
        record.get("type"),
        record.get("timestamp"),
        str(record.get("uuid") or ""),
    )
    attributes = {"source": QWEN_FORMAT}
    if kind == "user" and record.get("subtype") is None:
        chain.add(
            "human",
            when,
            identifier,
            actor="user",
            inputs={"text": _parts_text(parts)},
            attributes=attributes,
        )
    elif kind == "assistant":
        model = str(record.get("model") or "")
        meta = record.get("usageMetadata") if isinstance(record.get("usageMetadata"), dict) else {}
        calls = [
            p["functionCall"]
            for p in (parts if isinstance(parts, list) else [])
            if isinstance(p, dict) and isinstance(p.get("functionCall"), dict)
        ]
        outputs: dict[str, Any] = {"text": _parts_text(parts)}
        if calls:
            outputs["tool_calls"] = calls
        usage = gemini_usage(
            meta.get("promptTokenCount"),
            meta.get("candidatesTokenCount"),
            meta.get("cachedContentTokenCount"),
            meta.get("thoughtsTokenCount"),
            meta.get("toolUsePromptTokenCount"),
        )
        chain.add(
            "model",
            when,
            identifier,
            actor="assistant",
            model=model,
            provider=_provider(model, ""),
            outputs=outputs,
            usage=usage,
            attributes=attributes,
        )
    elif kind == "tool_result":
        result = (
            record.get("toolCallResult") if isinstance(record.get("toolCallResult"), dict) else {}
        )
        responses = [
            p["functionResponse"]
            for p in (parts if isinstance(parts, list) else [])
            if isinstance(p, dict) and isinstance(p.get("functionResponse"), dict)
        ]
        name = str((responses[0].get("name") if responses else "") or "tool")
        failed = bool(result.get("error")) or result.get("status") == "error"
        chain.add(
            "tool",
            when,
            identifier,
            actor=name,
            inputs={"name": name, "call_id": result.get("callId")},
            outputs={
                "result": responses[0].get("response") if responses else None,
                "is_error": failed,
            },
            attributes=attributes,
        )


def looks_like_qwen(record: dict[str, Any]) -> bool:
    message = record.get("message")
    return "uuid" in record and isinstance(message, dict) and "parts" in message


__all__ = ["QWEN_FORMAT", "looks_like_qwen", "qwen_session_events"]
