"""Normalize provider terminal states without discarding billed usage."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentine.models._usage import value


def reject_refused_tool_calls(result: dict[str, Any]) -> None:
    if not result.get("refusal") or not result.get("tool_calls"):
        return
    result["tool_calls"] = []
    warning = "discarded tool calls from a non-successful response"
    warnings = result.setdefault("warnings", [])
    if warning not in warnings:
        warnings.append(warning)


def chat_terminal(result: dict[str, Any], reason: Any) -> None:
    name = str(reason or "").lower().rsplit(".", 1)[-1]
    if name in {"tool_calls", "function_call"} and result.get("tool_calls"):
        reject_refused_tool_calls(result)
        return
    if name == "stop":
        reject_refused_tool_calls(result)
        return
    if name == "empty_choices":
        label = "provider returned no choices"
    elif name in {"tool_calls", "function_call"}:
        label = "chat ended for tool calls without a valid tool call"
    elif not name:
        label = "chat response omitted its terminal reason"
    else:
        label = f"chat ended: {name}"
    result["refusal"] = result.get("refusal") or label
    result.setdefault("warnings", []).append(label)
    reject_refused_tool_calls(result)


def response_terminal(
    result: dict[str, Any], response: Any, forced_status: str | None = None
) -> None:
    status = str(forced_status or value(response, "status", "") or "").lower()
    if status == "completed":
        reject_refused_tool_calls(result)
        return
    details = value(response, "incomplete_details") or value(response, "error")
    if isinstance(details, Mapping):
        reason = details.get("reason") or details.get("message") or details.get("code")
    else:
        reason = value(details, "reason") or value(details, "message") or value(details, "code")
    label = f"response {status or 'omitted its terminal status'}" + (
        f": {reason}" if reason else ""
    )
    result["refusal"] = result.get("refusal") or label
    result.setdefault("warnings", []).append(label)
    reject_refused_tool_calls(result)


def reject_unsafe_tool_calls(result: dict[str, Any]) -> None:
    calls = result.get("tool_calls") or []
    discarded = any(
        isinstance(call, Mapping)
        and isinstance(call.get("arguments"), Mapping)
        and call["arguments"].get("_truncated") is True
        for call in calls
    )
    warnings = result.setdefault("warnings", [])
    unsafe_warning = any(
        "tool calls truncated" in warning
        or ("tool arguments" in warning and "discarded" in warning)
        or "invalid JSON arguments" in warning
        for warning in warnings
    )
    replay_warning = bool(calls) and any(
        any(
            label in warning.lower()
            for label in ("continuation", "content blocks", "output", "reasoning", "thinking")
        )
        and any(state in warning.lower() for state in ("truncated", "discarded", "exceeded"))
        for warning in warnings
    )
    if not discarded and not unsafe_warning and not replay_warning:
        return
    label = "tool-call data exceeded safety limits; response is non-executable"
    result["tool_calls"] = []
    result["refusal"] = result.get("refusal") or label
    if label not in warnings:
        warnings.append(label)
