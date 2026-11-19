"""``tine monitor gate``: the inline monitor on the agent hook path (0.63).

An agent CLI runs this before each tool call with the call's JSON on stdin:

* Claude Code / Codex ``PreToolUse`` (``session_id``, ``tool_name``,
  ``tool_input``); Gemini CLI ``BeforeTool`` (same fields);
* generic ``{"protocol": "opentine-monitor/1", "session", "tool": {"name",
  "input"}, "reasoning"}``. Any payload may carry ``reasoning`` (the text the
  agent showed before the call); without it the verdict says ``unavailable``.

The action is digested as the MCP proxy digests a ``tools/call`` (``method``
``tools/call``, ``params`` ``{"name", "arguments"}``), so verdicts from both
paths compare. One JSON object leaves on stdout and the exit status is 0:

* Claude Code / Codex: ``{}`` to proceed; a block is
  ``hookSpecificOutput.permissionDecision = "deny"``; a replacement is
  ``"allow"`` with ``updatedInput``;
* Gemini CLI: ``{}`` or ``{"decision": "deny", "reason"}`` (no replacement:
  resample and defer block there);
* generic: ``{"protocol", "decision": "allow|block|replace", "verdict",
  "input", "reason"}``.

A payload or config that cannot be read proceeds unless ``--fail-closed``
(D12); an error while deciding in gate mode blocks.
"""

from __future__ import annotations

import json
import sys
from typing import IO, Any

PROTOCOL = "opentine-monitor/1"
MAX_PAYLOAD = 8 * 1024 * 1024
VENDOR = ("claude-code", "codex")


def normalize(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("the payload is not a JSON object")
    if payload.get("protocol") == PROTOCOL:
        tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else {}
        name, args = tool.get("name"), tool.get("input")
    else:
        name, args = payload.get("tool_name"), payload.get("tool_input")
    if not isinstance(name, str) or not name:
        raise ValueError("the payload names no tool")
    reasoning = payload.get("reasoning")
    return {"session": str(payload.get("session_id") or payload.get("session") or "hook"),
            "params": {"name": name, "arguments": args},
            "reasoning": reasoning if isinstance(reasoning, str) else None}  # fmt: skip


def respond(agent: str, decision: dict[str, Any]) -> dict[str, Any]:
    outcome, reason = decision["outcome"], decision.get("reason", "")
    replacement = decision.get("replacement") or {}
    if agent in VENDOR:
        if outcome == "forward":
            return {}
        out: dict[str, Any] = {"hookEventName": "PreToolUse",
                               "permissionDecision": "deny" if outcome == "block" else "allow",
                               "permissionDecisionReason": f"monitor: {reason}"}  # fmt: skip
        if outcome == "replace":
            out["updatedInput"] = replacement.get("arguments")
        return {"hookSpecificOutput": out}
    if agent == "gemini":
        return {} if outcome == "forward" else {"decision": "deny", "reason": f"monitor: {reason}"}
    word = {"forward": "allow", "block": "block", "replace": "replace"}[outcome]
    return {"protocol": PROTOCOL, "decision": word, "verdict": decision.get("verdict"),
            "input": replacement.get("arguments") if outcome == "replace" else None,
            "reason": reason}  # fmt: skip


def decide(raw: bytes, args: Any) -> dict[str, Any]:
    from opentine._key_hygiene import ed25519_private
    from opentine._monitor_gate import Gate
    from opentine._monitors import load
    from opentine.repo import Repo

    unreadable = {"outcome": "block" if args.fail_closed else "forward", "verdict": None,
                  "replacement": None}  # fmt: skip
    try:
        if len(raw) > MAX_PAYLOAD:
            raise ValueError("payload too large")
        event = normalize(json.loads(raw.decode("utf-8")))
        config = load(args.config)
        gate = Gate(config, repo=Repo.open(args.repo), key=ed25519_private(args.key),
                    session=event["session"], agent=args.agent or "generic")  # fmt: skip
    except Exception as exc:  # noqa: BLE001 - a hook never crashes the agent
        return {**unreadable, "reason": f"cannot gate: {type(exc).__name__}: {exc}"}
    if args.agent == "gemini":
        gate.alternate = None
    try:
        return gate.decide("tools/call", event["params"], reasoning=event["reasoning"])
    except Exception as exc:  # noqa: BLE001 - gate mode fails closed
        outcome = "block" if config["mode"] == "gate" else "forward"
        return {"outcome": outcome, "verdict": None, "replacement": None,
                "reason": f"monitor failed: {type(exc).__name__}"}  # fmt: skip


def run(args: Any, stream: IO[bytes] | None = None, out: IO[bytes] | None = None) -> int:
    try:
        raw = (stream or sys.stdin.buffer).read(MAX_PAYLOAD + 1)
    except Exception:  # noqa: BLE001
        raw = b""
    body = respond(args.agent or "generic", decide(raw, args))
    sink = out or sys.stdout.buffer
    sink.write(json.dumps(body, sort_keys=True).encode("utf-8") + b"\n")
    sink.flush()
    return 0


__all__ = ["PROTOCOL", "decide", "normalize", "respond", "run"]
