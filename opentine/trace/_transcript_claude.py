"""Import a Claude Code session transcript (``~/.claude/projects/*/*.jsonl``).

Each line is one record: ``user`` (a prompt, or the results of tool calls),
``assistant`` (one content block of a model response), and bookkeeping types
(``attachment``, ``system``, ``summary``, ...) that carry no model call and are
skipped. A response with several content blocks is written as several
``assistant`` lines sharing ``message.id``; every one repeats the response's
usage, so the lines are folded back into one model event and its usage is
counted once -- across the whole session: a subagent transcript repeats the
parent's response that spawned it (and siblings share some), so a response id
already billed is not recorded again (final pass 4, #6). Claude Code runs a tool
while the response is still streaming, so
``user`` tool-result lines can arrive between two lines of one response; they
are held back and recorded after its model event rather than splitting it.
Older Claude Code versions wrote a message-start placeholder for
``output_tokens`` on early blocks, so the largest reported value wins.

Usage follows the Anthropic convention (cache reads and writes beside
``input_tokens``; the TTL split under ``cache_creation``). Current Claude Code
writes each subagent's transcript beside the session, in
``<session>/subagents/agent-*.jsonl``; those are imported too, each hung under
the tool step that spawned it (:mod:`opentine.trace._transcript_agents`).
"""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Any

from opentine.trace import _transcript_claude_lines as lines_
from opentine.trace._transcript_claude_lines import FORMAT
from opentine.trace._transcript_common import (
    Chain,
    anthropic_usage,
    bounded_id,
    count,
    label,
    note_skipped,
    text_of,
)
from opentine.trace._transcript_usage import claude_tier
from opentine.trace.schema import TraceEvent


class _Builder:
    def __init__(
        self,
        trace_id: str = "",
        prefix: str = "",
        parent: str | None = None,
        billed: set[str] | None = None,
    ) -> None:
        self.chain: Chain | None = None
        self.billed = set() if billed is None else billed  # response ids, session-wide
        self.pending: list[dict[str, Any]] = []
        self.held: list[dict[str, Any]] = []  # tool results inside an open response
        self.tool_names: dict[str, str] = {}
        self.agents: dict[str, str] = {}  # subagent id -> the tool step that spawned it
        self._chain_args = (trace_id, prefix, parent)

    def _chain(self, record: dict[str, Any]) -> Chain:
        if self.chain is None:
            trace_id, prefix, parent = self._chain_args
            session = trace_id or str(record.get("sessionId") or "claude-code")
            self.chain = Chain(session, prefix=prefix, parent=parent)
        return self.chain

    def feed(self, record: dict[str, Any]) -> None:
        kind = record.get("type")
        message = record.get("message")
        if isinstance(message, dict):
            # The fields a response is built from, coerced once here: a held
            # line is only read later, inside another record's flush.
            message = {
                **message,
                "content": lines_.listed(message.get("content")),
                "usage": message.get("usage") if isinstance(message.get("usage"), dict) else {},
            }
            record = {**record, "message": message}
        if kind == "assistant" and isinstance(message, dict):
            if self.pending and self.pending[0]["message"].get("id") != message.get("id"):
                self.flush()
            self.pending.append(record)
            return
        if self.pending and lines_.tool_results_only(record, message):
            self.held.append(record)
            return
        self.flush()
        if kind == "user" and isinstance(message, dict) and not record.get("isMeta"):
            self._user(record, message)

    def _user(self, record: dict[str, Any], message: dict[str, Any]) -> None:
        chain = self._chain(record)
        content = message.get("content")
        blocks = content if isinstance(content, list) else []
        results = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool_result"]
        for block in results:
            call = str(block.get("tool_use_id") or "")
            chain.add(
                "tool",
                record.get("timestamp"),
                f"tool:{call}" if call else str(record.get("uuid") or ""),
                actor=self.tool_names.get(call, "tool"),
                inputs={"name": self.tool_names.get(call, "tool"), "tool_use_id": call},
                outputs={
                    "result": text_of(block.get("content")),
                    "is_error": bool(block.get("is_error")),
                },
                attributes=lines_.flags(record),
            )
            spawned = record.get("toolUseResult")
            if isinstance(spawned, dict) and isinstance(spawned.get("agentId"), str):
                self.agents[bounded_id(spawned["agentId"], "agentId")] = chain.events[-1].span_id
        if results:
            return
        text = text_of(content)
        if text not in (None, "", []):
            chain.add(
                "human",
                record.get("timestamp"),
                str(record.get("uuid") or ""),
                actor="user",
                inputs={"text": text},
                attributes=lines_.flags(record),
            )

    def flush(self) -> None:
        if self.pending:
            self._response(self.pending)
        self.pending, held, self.held = [], self.held, []
        for record in held:
            self._user(record, record["message"])

    def _response(self, lines: list[dict[str, Any]]) -> None:
        first = lines[0]
        message = first["message"]
        model = str(message.get("model") or "")
        usage_line = max(
            lines,
            key=lambda line: count((line["message"].get("usage") or {}).get("output_tokens")) or 0,
        )
        raw_usage = usage_line["message"].get("usage") or {}
        texts: list[str] = []
        calls: list[dict[str, Any]] = []
        for line in lines:
            for block in line["message"].get("content") or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text" and isinstance(block.get("text"), str):
                    texts.append(block["text"])
                elif block.get("type") == "tool_use":
                    call = {
                        "id": block.get("id"),
                        "name": block.get("name"),
                        "input": block.get("input"),
                    }
                    calls.append(call)
                    # Every tool_result naming this call repeats the name: clip it.
                    self.tool_names[str(block.get("id") or "")] = label(block.get("name") or "tool")
        synthetic = model == "<synthetic>" or bool(first.get("isApiErrorMessage"))
        keys = {
            bounded_id(key, "response")
            for key in (message.get("id"), first.get("requestId"))
            if isinstance(key, str) and key
        }
        if not synthetic and keys & self.billed:
            return  # a context copy of a response this session already recorded
        self.billed |= keys
        attributes = lines_.flags(first)
        if isinstance(raw_usage, dict) and raw_usage.get("speed") not in (None, "standard"):
            attributes["speed"] = label(raw_usage.get("speed"))[:32]
        geo = raw_usage if isinstance(raw_usage, dict) else {}
        tier = claude_tier(geo.get("speed"), geo.get("inference_geo"))
        outputs: dict[str, Any] = {"text": "".join(texts)}
        if calls:
            outputs["tool_calls"] = calls
        self._chain(first).add(
            "error" if synthetic else "model",
            first.get("timestamp"),
            f"message:{message.get('id') or first.get('uuid') or ''}",
            actor="assistant",
            model="" if synthetic else model,
            provider="" if synthetic else lines_.provider(model),
            outputs=outputs,
            usage={} if synthetic else anthropic_usage(raw_usage),
            inputs={"service_tier": tier} if tier and not synthetic else {},
            attributes=attributes,
        )


def claude_transcript_events(source: str | Path | list[Any]) -> list[TraceEvent]:
    from opentine.trace._transcript_agents import build, with_subagents

    builder = _Builder()
    skipped = build(source, builder)
    events = builder.chain.events if builder.chain else []
    if events and isinstance(source, (str, Path)):
        shared = partial(_Builder, billed=builder.billed)
        events = with_subagents(Path(source), events, builder.agents, shared)
    return note_skipped(events, skipped)


def looks_like_claude(record: dict[str, Any]) -> bool:
    return (
        isinstance(record.get("sessionId"), str)
        and record.get("type")
        in (
            "user",
            "assistant",
            "summary",
            "system",
            "attachment",
        )
        and "uuid" in record
        and "provenance" not in record
    )


__all__ = ["FORMAT", "claude_transcript_events", "looks_like_claude"]
