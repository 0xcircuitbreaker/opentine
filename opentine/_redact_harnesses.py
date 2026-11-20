"""Per-harness telemetry patterns for :mod:`opentine._redact_telemetry` (Unreleased).

Each entry of :data:`HARNESSES` describes one agent CLI's machine-readable stream:

* ``markers``: text that must appear for the harness to be looked for at all;
* ``kind_keys``: the keys naming a record's kind, in order (the CLI's own stream
  uses ``type``; OpenTine's claude-code adapter writes ``event``);
* ``types``: record kinds that are the harness's when they also carry one of
  the ``id_keys`` (a session or thread id), so other JSON is left untouched;
* ``drop``: record kinds removed entirely;
* ``reduce``: ``(kind, subtype)`` (``subtype`` ``None`` matches any) to the only
  keys such a record keeps; ``placeholders`` replace a kept key's value;
* ``strip``: keys removed at any depth of an owned record, and OTel
  ``{"key": ..., "value": ...}`` attributes named by one of them;
* ``opaque``: keys whose value (a tool's own arguments) is never touched;
* ``session_path`` / ``path_hint``: a session id inside a path the harness
  writes, replaced by ``<SESSION>`` anywhere in text.

Add a harness by adding an entry; nothing else changes.
"""

from __future__ import annotations

import re
from typing import Any

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_SEP = r"(?:\\+|/)"

_CLAUDE_INIT = frozenset(
    {"type", "subtype", "event", "model", "tools", "cwd", "permissionMode"}
)  # fmt: skip

HARNESSES: dict[str, dict[str, Any]] = {
    "claude-code-stream-json": {
        "markers": ('"session_id"', '"sessionId"'),
        "kind_keys": ("type", "event"),
        "id_keys": ("session_id", "sessionId"),
        "types": frozenset({"system", "init", "assistant", "user", "result", "stream_event"}),
        "drop": frozenset({"rate_limit_event"}),
        "reduce": {("system", "init"): _CLAUDE_INIT, ("init", None): _CLAUDE_INIT},
        "placeholders": {"cwd": "<CWD>"},
        "strip": frozenset(
            {
                "session_id",
                "sessionId",
                "request_id",
                "requestId",
                "uuid",
                "parent_tool_use_uuid",
                "persistedOutputPath",
                "inference_geo",
            }
        ),
        # A tool's own arguments are the agent's data, never telemetry.
        "opaque": frozenset({"input", "parameters"}),
        "path_hint": ".claude",
        "session_path": re.compile(
            r"(\.claude" + _SEP + r"projects" + _SEP + r"[^/\\\s\"']+" + _SEP + r")" + _UUID
        ),
    },
    "gemini-cli-stream-json": {
        "markers": ('"session_id"',),
        "kind_keys": ("type",),
        "id_keys": ("session_id",),
        "types": frozenset({"init", "message", "tool_use", "tool_result", "result"}),
        "drop": frozenset(),
        "reduce": {("init", None): frozenset({"type", "model"})},
        "placeholders": {},
        "strip": frozenset({"session_id"}),
        "opaque": frozenset({"parameters"}),
    },
    "codex-exec-json": {
        "markers": ('"thread_id"',),
        "kind_keys": ("type",),
        "id_keys": ("thread_id",),
        "types": frozenset({"thread.started"}),
        "drop": frozenset(),
        "reduce": {},
        "placeholders": {},
        "strip": frozenset({"thread_id"}),
        "opaque": frozenset(),
    },
}


def kind_of(record: dict[str, Any], spec: dict[str, Any]) -> Any:
    """The record's kind under *spec*: its first present ``kind_keys`` value."""
    for key in spec["kind_keys"]:
        if key in record:
            return record[key]
    return None


def owns(record: dict[str, Any], spec: dict[str, Any]) -> bool:
    """Whether *record* is this harness's (a listed kind carrying an id)."""
    return kind_of(record, spec) in spec["types"] and any(k in record for k in spec["id_keys"])


__all__ = ["HARNESSES", "kind_of", "owns"]
