"""JSON Schemas for ``opentine-hook/1`` (docs/spec/hook-1.md) and ``tine hook resume`` (0.46)."""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import doc, open_, opt

STR: dict[str, Any] = {"type": "string"}
KINDS = ["prompt", "tool", "turn_end", "session_end"]

EVENT = open_(["protocol", "event", "session"], {
    "protocol": {"const": "opentine-hook/1"}, "event": {"enum": KINDS},
    "session": {"type": "string", "minLength": 1}, "prompt": {}, "message": {}, "cwd": STR,
    "tool": open_([], {"name": STR, "input": {}, "output": {}}),
})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-hook-1": doc("opentine-hook-1", "opentine-hook/1",
        "One event a hook sends on the stdin of `tine hook capture` (the generic form; vendor "
        "payloads are translated to it, see docs/spec/hook-1.md), or the JSON response it "
        "writes on stdout (`ok`, and `ref`, `run`, `steps`, `steer` or `reason`).",
        {"anyOf": [EVENT, open_(["protocol", "ok"], {
            "protocol": {"const": "opentine-hook/1"}, "ok": {"type": "boolean"},
            "event": {"enum": KINDS}, "ref": STR, "run": STR,
            "steps": {"type": "integer", "minimum": 0}, "reason": STR,
            "steer": {"type": "array", "items": STR}})]}),
    "tine-cli-hook-resume-1": doc("tine-cli-hook-resume-1", "tine hook resume --dry-run",
        "The plan `tine hook resume --dry-run` prints: the agent CLI's resume argv (run "
        "without a shell) and the capture ref the message would be recorded on.",
        open_(["command", "agent", "session", "argv", "recorded"], {
            "command": {"const": "hook resume"}, "agent": {"enum": ["claude-code", "codex",
            "gemini"]}, "session": STR, "argv": {"type": "array", "items": STR, "minItems": 1},
            "recorded": opt(STR), "dry_run": {"type": "boolean"}})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {"hook resume": "tine-cli-hook-resume-1"}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
