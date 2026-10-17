"""Cline, OpenClaw and OpenHands dialects.

* Cline ``--json`` (docs.cline.bot CLI reference): ``agent_event`` lines wrap
  SDK events; ``usage`` reports one call's tokens and USD cost; ``run_result``
  names the model.
* OpenClaw ``agent exec --json``: one envelope with model, provider, usage and
  ``costUsd``.
* OpenHands ``--headless --json``: ``action`` / ``observation`` events.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentine.harnesses._dialect_base import (
    done_step,
    error_step,
    model_step,
    money,
    text_of,
    think_step,
    tool_step,
    usage,
)
from opentine.harnesses._dialect_harness import Dialect
from opentine.harnesses._types import HarnessStep


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


class Cline(Dialect):
    cli = "cline"

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        kind = data.get("type")
        if kind == "agent_event":
            event = _map(data.get("event"))
            name = event.get("type")
            if name == "usage":
                tokens = usage(
                    input=event.get("inputTokens"),
                    output=event.get("outputTokens"),
                    cache_read=event.get("cacheReadTokens"),
                    cache_write=event.get("cacheWriteTokens"),
                )
                return [
                    model_step(self.model, self.provider, tokens, cost=money(event.get("cost")))
                ]
            if name == "error":
                return [error_step(event.get("error") or event.get("message") or event, self.model)]
            if name == "content_end" and str(event.get("text") or "").strip():
                return [think_step(event.get("text"), self.model)]
            return []
        if kind == "run_result":
            self.set_model(data.get("model"))
            reason = str(data.get("finishReason") or "")
            return [
                done_step(
                    data.get("text"),
                    self.cli,
                    self.model,
                    failed=reason in ("error", "aborted"),
                    finish_reason=reason,
                    iterations=data.get("iterations"),
                )
            ]
        if kind in ("hook_event", "team_event", "run_start", "run_aborted"):
            return []
        return None


class OpenClaw(Dialect):
    cli = "openclaw"

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        if "status" not in data or ("final" not in data and "ok" not in data):
            return None
        self.set_model(data.get("model"), data.get("provider"))
        raw = _map(data.get("usage"))
        tokens = usage(
            input=raw.get("input"),
            output=raw.get("output"),
            cache_read=raw.get("cacheRead"),
            cache_write=raw.get("cacheWrite"),
        )
        steps = (
            [
                model_step(
                    self.model,
                    self.provider,
                    tokens,
                    event="run-usage",
                    assistant_turns=data.get("assistantTurns"),
                )
            ]
            if tokens
            else []
        )
        failed = data.get("status") != "ok"
        error = _map(data.get("error"))
        steps.append(
            done_step(
                error.get("message") if failed else data.get("final"),
                self.cli,
                self.model,
                cost=money(data.get("costUsd")),
                failed=failed,
                status=data.get("status"),
                tool_summary=data.get("toolSummary"),
                session_id=data.get("sessionId"),
            )
        )
        return steps


class OpenHands(Dialect):
    cli = "openhands"

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        kind = data.get("type")
        if kind == "action":
            arguments = {key: value for key, value in data.items() if key not in ("type", "action")}
            return [tool_step(data.get("action"), arguments, "", self.model)]
        if kind == "observation":
            content = data.get("content")
            return [
                think_step(text_of(content) or str(content or ""), self.model, event="observation")
            ]
        return None


__all__ = ["Cline", "OpenClaw", "OpenHands"]
