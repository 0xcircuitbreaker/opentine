"""SPEC 8.16 / docs/spec/hook-1.md: the ``opentine-hook/1`` event envelope, stdlib only (0.46).

The pyz's port of :func:`opentine._hook_protocol.normalize` (with the vendor
translations of :mod:`opentine._hook_dialects`) and of
:func:`opentine._hook_mailbox.vendor_response`, answering the conformance ops
``hook.normalize`` and ``hook.respond`` without importing opentine.
"""

from __future__ import annotations

from typing import Any

PROTOCOL = "opentine-hook/1"
KINDS = ("prompt", "tool", "turn_end", "session_end")
EVENTS = {"UserPromptSubmit": "prompt", "BeforeAgent": "prompt", "PreInvocation": "prompt",
          "PostToolUse": "tool", "AfterTool": "tool", "Stop": "turn_end",
          "AfterAgent": "turn_end", "SessionEnd": "session_end"}  # fmt: skip
CONTINUE = {"claude-code": "block", "codex": "block", "gemini": "deny"}


def _antigravity(payload: dict[str, Any], event: str) -> dict[str, Any]:
    call = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    out: dict[str, Any] = {"hook_event_name": event, "session_id": payload.get("conversationId")}
    paths = payload.get("workspacePaths")
    if isinstance(paths, list) and paths and isinstance(paths[0], str):
        out["cwd"] = paths[0]
    if event == "PreInvocation":
        out["prompt"] = payload.get("lastUserInput")
    elif event == "PostToolUse":
        out["tool_name"], out["tool_input"] = call.get("name"), call.get("args")
        if payload.get("error") is not None:
            out["tool_response"] = {"error": payload.get("error")}
    return out


def _translate(payload: dict[str, Any], hint: str | None) -> dict[str, Any]:
    if hint and "hook_event_name" not in payload and "conversationId" in payload:
        return _antigravity(payload, hint)
    if hint and "hook_event_name" not in payload and "protocol" not in payload:
        payload = {**payload, "hook_event_name": hint}
    if "last_assistant_message" not in payload and "prompt_response" in payload:
        payload = {**payload, "last_assistant_message": payload["prompt_response"]}
    return payload


def _name(value: Any) -> str:
    return value[:256] if isinstance(value, str) else ""


def normalize(payload: Any, hint: str | None = None) -> dict[str, Any] | None:
    """The protocol event of one payload, or ``None`` when it is refused."""
    if not isinstance(payload, dict):
        return None
    payload = _translate(payload, hint)
    kind = payload.get("event") if payload.get("protocol") == PROTOCOL else None
    vendor = payload.get("hook_event_name")
    kind = kind or (EVENTS.get(vendor) if isinstance(vendor, str) else None)
    session = payload.get("session") or payload.get("session_id")
    if kind not in KINDS or not isinstance(session, str) or not session:
        return None
    tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else {}
    return {"event": kind, "session": session[:512],
            "tool_name": _name(tool.get("name")) or _name(payload.get("tool_name")),
            "cwd": payload.get("cwd") if isinstance(payload.get("cwd"), str) else ""}  # fmt: skip


def normalize_case(value: dict[str, Any]) -> dict[str, Any]:
    """A conformance ``hook.normalize`` input -> its output."""
    hint = value.get("hint")
    event = normalize(value.get("payload"), hint if isinstance(hint, str) else None)
    if event is None:
        return {"ok": False, "event": None, "session": None, "tool_name": None, "cwd": None}
    return {"ok": True, **event}


def respond_case(value: dict[str, Any]) -> dict[str, Any]:
    """A conformance ``hook.respond`` input -> what the vendor CLI reads on stdout."""
    agent, steer = value["agent"], list(value["steer"])
    if steer and agent in CONTINUE:
        return {"stdout": {"decision": CONTINUE[agent], "reason": "\n\n".join(steer)}}
    return {"stdout": {"suppressOutput": True} if agent == "claude-code" else {}}


__all__ = ["normalize", "normalize_case", "respond_case"]
