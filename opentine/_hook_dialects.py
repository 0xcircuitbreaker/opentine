"""Vendor hook payloads that are not Claude-shaped, translated for ``opentine-hook/1``.

* **GitHub Copilot CLI**: configured with PascalCase event names
  (``UserPromptSubmit``, ``PostToolUse``, ``Stop``, ``SessionEnd``) it sends
  the snake_case payload with ``hook_event_name`` and ``session_id``, but the
  tool result is ``tool_result`` (``result_type``, ``text_result_for_llm``),
  not ``tool_response``
  (docs.github.com/en/copilot/reference/hooks-configuration).
* **Factory Droid**: Claude-shaped as is (``hook_event_name``, ``session_id``,
  ``tool_name``/``tool_input``/``tool_response``, ``prompt``)
  (docs.factory.com/reference/hooks-reference).
* **Google Antigravity**: camelCase, and the payload does not name its event,
  so the shim passes ``--event``: ``PreInvocation`` (``lastUserInput``),
  ``PostToolUse`` (``toolCall.name``/``args``, ``error``), ``Stop``
  (``terminationReason``), all keyed by ``conversationId``
  (antigravity.google/docs/hooks).
"""

from __future__ import annotations

from typing import Any

#: Vendor event names beyond Claude Code's, Codex's and Gemini CLI's.
EXTRA_EVENTS = {"PreInvocation": "prompt"}
#: ``--event`` values ``tine hook capture`` accepts (the agent's own event name).
HINTS = ("PreInvocation", "PostToolUse", "Stop", "SessionEnd", "UserPromptSubmit")


def _antigravity(payload: dict[str, Any], event: str) -> dict[str, Any]:
    call = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    out: dict[str, Any] = {"hook_event_name": event, "session_id": payload.get("conversationId")}
    paths = payload.get("workspacePaths")
    if isinstance(paths, list) and paths and isinstance(paths[0], str):
        out["cwd"] = paths[0]
    if event == "PreInvocation":
        out["prompt"] = payload.get("lastUserInput")
    elif event == "PostToolUse":
        out["tool_name"] = call.get("name")
        out["tool_input"] = call.get("args")
        if payload.get("error") is not None:
            out["tool_response"] = {"error": payload.get("error")}
    return out


def translate(payload: Any, event: str | None) -> Any:
    """*payload* in the Claude-shaped vendor form :func:`normalize` reads."""
    if not isinstance(payload, dict):
        return payload
    if event and "hook_event_name" not in payload and "conversationId" in payload:
        return _antigravity(payload, event)
    if event and "hook_event_name" not in payload and "protocol" not in payload:
        payload = {**payload, "hook_event_name": event}
    if "tool_response" not in payload and "tool_result" in payload:  # Copilot CLI
        result = payload["tool_result"]
        if isinstance(result, dict) and "text_result_for_llm" in result:
            result = {"type": result.get("result_type"), "text": result["text_result_for_llm"]}
        payload = {**payload, "tool_response": result}
    return payload


__all__ = ["EXTRA_EVENTS", "HINTS", "translate"]
