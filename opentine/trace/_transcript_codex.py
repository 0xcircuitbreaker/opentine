"""Import a Codex CLI session rollout (``~/.codex/sessions/**/rollout-*.jsonl``).

Each line is ``{"timestamp", "type", "payload"}``. ``session_meta`` names the
session and its ``model_provider``; ``turn_context`` names the model for the
turn that follows; ``response_item`` carries messages, tool calls
(``function_call``/``custom_tool_call``/``local_shell_call``) and their outputs;
``event_msg`` carries the user's prompt and, after each model call, a
``token_count`` whose ``info.last_token_usage`` is that call's usage.

Codex re-emits ``token_count`` when nothing was spent (rate-limit refreshes, a
resumed session), so a call is counted only when the running
``total_token_usage`` moved. Usage follows the OpenAI convention: input includes
``cached_input_tokens``, output includes ``reasoning_output_tokens``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine.trace._provider_alias import canonical_provider
from opentine.trace._transcript_common import (
    SHAPE_ERRORS,
    Chain,
    inclusive_usage,
    label,
    note_skipped,
    records,
    text_of,
)
from opentine.trace.schema import TraceEvent

FORMAT = "codex-session"
_TOOL_CALLS = ("function_call", "custom_tool_call", "local_shell_call", "web_search_call")
_TOOL_OUTPUTS = ("function_call_output", "custom_tool_call_output")


class _Builder:
    def __init__(self) -> None:
        self.chain = Chain("codex")
        self.model = ""
        self.provider = "openai"
        self.total: Any = None
        self.calls: dict[str, dict[str, Any]] = {}
        self.said: list[str] = []
        self.pending_calls: list[dict[str, Any]] = []

    def feed(self, record: dict[str, Any]) -> None:
        payload = record.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        when = record.get("timestamp")
        kind = record.get("type")
        if kind == "session_meta":
            self.chain.trace_id = str(payload.get("id") or payload.get("session_id") or "codex")
            self.provider = (
                canonical_provider(payload.get("model_provider") or "openai") or "openai"
            )
        elif kind == "turn_context":
            self.model = str(payload.get("model") or self.model)
        elif kind == "event_msg":
            self._event(payload, when)
        elif kind == "response_item":
            self._item(payload, when)

    def _event(self, payload: dict[str, Any], when: Any) -> None:
        kind = payload.get("type")
        if kind == "user_message" and payload.get("message"):
            self.chain.add("human", when, "", actor="user", inputs={"text": payload["message"]})
        elif kind == "agent_message" and isinstance(payload.get("message"), str):
            self.said.append(payload["message"])
        elif kind == "token_count":
            info = payload.get("info")
            info = info if isinstance(info, dict) else {}
            last, total = info.get("last_token_usage"), info.get("total_token_usage")
            if not isinstance(last, dict) or total == self.total:
                return
            self.total = total
            outputs: dict[str, Any] = {"text": "\n".join(self.said)}
            if self.pending_calls:
                outputs["tool_calls"] = self.pending_calls
            self.said, self.pending_calls = [], []
            self.chain.add(
                "model",
                when,
                "",
                actor="assistant",
                model=self.model,
                provider=self.provider,
                outputs=outputs,
                usage=inclusive_usage(
                    last.get("input_tokens"),
                    last.get("cached_input_tokens"),
                    last.get("output_tokens"),
                    last.get("reasoning_output_tokens"),
                ),
                attributes={"source": FORMAT},
            )

    def _item(self, payload: dict[str, Any], when: Any) -> None:
        kind = payload.get("type")
        if kind in _TOOL_CALLS:
            call_id = str(payload.get("call_id") or payload.get("id") or "")
            call = {
                "id": call_id,
                "name": label(payload.get("name") or kind),
                "arguments": payload.get("arguments", payload.get("input", payload.get("action"))),
            }
            self.calls[call_id] = call
            self.pending_calls.append(call)
            if kind == "web_search_call":
                self._tool(call, payload.get("status"), when)
        elif kind in _TOOL_OUTPUTS:
            # A call's arguments are recorded with its first output only: a
            # second output naming the same call must not copy them again.
            call = self.calls.pop(str(payload.get("call_id") or ""), {})
            self._tool(
                call or {"id": payload.get("call_id"), "name": "tool"}, payload.get("output"), when
            )

    def _tool(self, call: dict[str, Any], output: Any, when: Any) -> None:
        self.chain.add(
            "tool",
            when,
            f"tool:{call.get('id') or ''}",
            actor=str(call.get("name") or "tool"),
            inputs={"name": call.get("name"), "arguments": call.get("arguments")},
            outputs={"result": text_of(output)},
            attributes={"source": FORMAT},
        )


def codex_session_events(source: str | Path | list[Any]) -> list[TraceEvent]:
    builder = _Builder()
    skipped = 0
    for record in records(source):
        try:
            builder.feed(record)
        except SHAPE_ERRORS:
            skipped += 1
    return note_skipped(builder.chain.events, skipped)


def looks_like_codex(record: dict[str, Any]) -> bool:
    return isinstance(record.get("payload"), dict) and record.get("type") in (
        "session_meta",
        "turn_context",
        "response_item",
        "event_msg",
    )


__all__ = ["FORMAT", "codex_session_events", "looks_like_codex"]
