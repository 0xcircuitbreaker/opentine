"""Import Gemini CLI session records.

**Gemini CLI** (``~/.gemini/tmp/<project>/chats/session-*.jsonl``) appends one
JSON record per line: a metadata record (``sessionId``, ``projectHash``), then
message records (``{id, timestamp, type: "user"|"gemini"|"info"|"error"|
"warning", content, toolCalls?, tokens?, model?}``), where a later record with
the same ``id`` replaces an earlier one, plus ``$patch`` records that fill in
tool results and ``$rewindTo``/``removeIds`` records. A rewind removes messages
from the conversation, but their API calls were still made and billed, so they
are kept here. The legacy ``.json`` file holds the same messages under
``messages``. ``tokens`` is the response's usage metadata, renamed
(``input`` = ``promptTokenCount``, which includes ``cached``).
Qwen Code's own log is read by :mod:`opentine.trace._transcript_qwen`.
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
    text_of,
)
from opentine.trace.schema import TraceEvent

GEMINI_FORMAT = "gemini-session"


def _provider(model: str, default: str) -> str:
    lowered = model.lower()
    if lowered.startswith("gemini"):
        return "google"
    if lowered.startswith(("qwen", "qwq")):
        return "qwen"
    return default


def _parts_text(parts: Any) -> Any:
    if not isinstance(parts, list):
        return text_of(parts)
    texts = [
        part["text"]
        for part in parts
        if isinstance(part, dict) and isinstance(part.get("text"), str) and not part.get("thought")
    ]
    return "".join(texts) if texts else text_of(parts)


def gemini_session_events(source: str | Path | list[Any]) -> list[TraceEvent]:
    messages: dict[str, dict[str, Any]] = {}
    indexes: dict[str, tuple[dict[str, Any], dict[Any, dict[str, Any]]]] = {}
    session = "gemini"
    skipped = 0
    for record in records(source):
        try:
            session = _read(record, messages, indexes, session)
        except SHAPE_ERRORS:
            skipped += 1
    chain = Chain(session)
    for message in messages.values():
        try:
            _gemini_message(chain, message)
        except SHAPE_ERRORS:
            skipped += 1
    return note_skipped(chain.events, skipped)


def _read(
    record: dict[str, Any],
    messages: dict[str, dict[str, Any]],
    indexes: dict[str, tuple[dict[str, Any], dict[Any, dict[str, Any]]]],
    session: str,
) -> str:
    """Fold one session record into *messages*; return the session id so far."""
    if isinstance(record.get("messages"), list):  # legacy whole-file .json
        for message in record["messages"]:
            if isinstance(message, dict) and message.get("id") is not None:
                messages[str(message["id"])] = message
        return str(record.get("sessionId") or session)
    if "$patch" in record:
        _patch(messages, indexes, record["$patch"])
    elif record.get("id") is not None and record.get("type") is not None:
        messages[str(record["id"])] = record
    elif isinstance(record.get("sessionId"), str):
        return record["sessionId"]
    return session


def _patch(
    messages: dict[str, dict[str, Any]],
    indexes: dict[str, tuple[dict[str, Any], dict[Any, dict[str, Any]]]],
    patch: Any,
) -> None:
    updates = [patch] if isinstance(patch, dict) and patch.get("id") else []
    if isinstance(patch, dict) and isinstance(patch.get("updates"), list):
        updates += [item for item in patch["updates"] if isinstance(item, dict)]
    for update in updates:
        key = str(update.get("id"))
        target = messages.get(key)
        if target is None:
            continue
        if "content" in update:
            target["content"] = update["content"]
        tools = update.get("toolCalls")
        if not tools or not isinstance(tools, list):
            continue
        for tool in tools:
            if isinstance(tool, dict):
                call = _calls(indexes, key, target).get(_key(tool.get("id")))
                if call is not None:
                    call["result"] = tool.get("result")


def _listed(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _calls(
    indexes: dict[str, tuple[dict[str, Any], dict[Any, dict[str, Any]]]],
    key: str,
    target: dict[str, Any],
) -> dict[Any, dict[str, Any]]:
    """The message's tool calls by id, built once per message record.

    Built lazily and kept until the message record itself is replaced, so a
    stream of updates costs O(updates + calls), not O(updates x calls). A
    result attaches to the first call with its id only: a duplicated id must
    not copy one result onto every call that shares it.
    """
    cached = indexes.get(key)
    if cached is not None and cached[0] is target:
        return cached[1]
    index: dict[Any, dict[str, Any]] = {}
    for call in _listed(target.get("toolCalls")):
        if isinstance(call, dict):
            index.setdefault(_key(call.get("id")), call)
    indexes[key] = (target, index)
    return index


def _key(identifier: Any) -> Any:
    """A hashable lookup key for a tool-call id (ids are normally strings)."""
    try:
        hash(identifier)
    except TypeError:
        return ("unhashable", repr(identifier)[:256])
    return identifier


def _gemini_message(chain: Chain, message: dict[str, Any]) -> None:
    kind, when = message.get("type"), message.get("timestamp")
    identifier = str(message.get("id") or "")
    attributes = {"source": GEMINI_FORMAT}
    if kind == "user":
        chain.add(
            "human",
            when,
            identifier,
            actor="user",
            inputs={"text": text_of(message.get("content"))},
            attributes=attributes,
        )
    elif kind == "error":
        chain.add(
            "error",
            when,
            identifier,
            inputs={"error": text_of(message.get("content"))},
            attributes=attributes,
        )
    elif kind == "gemini":
        model = str(message.get("model") or "")
        tokens = message.get("tokens") if isinstance(message.get("tokens"), dict) else {}
        calls = [call for call in _listed(message.get("toolCalls")) if isinstance(call, dict)]
        outputs: dict[str, Any] = {"text": text_of(message.get("content"))}
        if calls:
            outputs["tool_calls"] = [
                {"id": c.get("id"), "name": c.get("name"), "arguments": c.get("args")}
                for c in calls
            ]
        usage = gemini_usage(
            tokens.get("input"),
            tokens.get("output"),
            tokens.get("cached"),
            tokens.get("thoughts"),
            tokens.get("tool"),
        )
        chain.add(
            "model",
            when,
            identifier,
            actor="gemini",
            model=model,
            provider=_provider(model, "google"),
            outputs=outputs,
            usage=usage,
            attributes=attributes,
        )
        for call in calls:
            chain.add(
                "tool",
                call.get("timestamp") or when,
                f"tool:{call.get('id') or ''}",
                actor=str(call.get("name") or "tool"),
                inputs={"name": call.get("name"), "arguments": call.get("args")},
                outputs={"result": text_of(call.get("result")), "status": call.get("status")},
                attributes=attributes,
            )


def looks_like_gemini(record: dict[str, Any]) -> bool:
    return isinstance(record.get("projectHash"), str) or (
        record.get("type") in ("user", "gemini", "info") and "id" in record and "uuid" not in record
    )


__all__ = [
    "GEMINI_FORMAT",
    "gemini_session_events",
    "looks_like_gemini",
]
