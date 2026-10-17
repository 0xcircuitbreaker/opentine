"""Per-record helpers for the Claude Code transcript importer."""

from __future__ import annotations

from typing import Any

from opentine.trace._transcript_common import bounded_id

FORMAT = "claude-code-transcript"


def provider(model: str) -> str:
    """Claude Code names a Bedrock or Vertex deployment by the model id it sends."""
    lowered = model.lower()
    if lowered.startswith(("anthropic.", "us.anthropic.", "eu.anthropic.", "global.anthropic.")):
        return "bedrock"
    if "@" in lowered:
        return "vertex"
    return "anthropic"


def tool_results_only(record: dict[str, Any], message: Any) -> bool:
    """A ``user`` line that only returns tool results (never a new prompt)."""
    if record.get("type") != "user" or not isinstance(message, dict) or record.get("isMeta"):
        return False
    content = message.get("content")
    return (
        isinstance(content, list)
        and bool(content)
        and all(isinstance(b, dict) and b.get("type") == "tool_result" for b in content)
    )


def flags(record: dict[str, Any]) -> dict[str, Any]:
    flags: dict[str, Any] = {"source": FORMAT}
    if record.get("isSidechain"):
        flags["claude_code.sidechain"] = True
    # One user line stamps these on each of its tool results: bound them like
    # the session id, so a huge id is not copied once per result block.
    for key in ("requestId", "promptId", "agentId"):
        if isinstance(record.get(key), str):
            flags[f"claude_code.{key}"] = bounded_id(record[key], key)
    return flags


def listed(content: Any) -> Any:
    # A user line's content may be plain text; any other non-list is no content.
    return content if isinstance(content, (list, str)) else []


__all__ = ["FORMAT", "flags", "listed", "provider", "tool_results_only"]
