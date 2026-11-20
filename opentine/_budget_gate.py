"""The budget gate on the agent hook path and in ``tine mcp-proxy`` (0.69).

``tine budget gate SUBJECT --key KEY`` runs before each tool call with the
hook's JSON on stdin, like ``tine monitor gate``. It reads the ledger, and when
a limit is reached it refuses the call: Claude Code / Codex get
``hookSpecificOutput.permissionDecision = "deny"``, Gemini CLI ``{"decision":
"deny"}``, anything else ``{"protocol": "opentine-budget/1", "decision":
"allow"|"deny"|"escalate", "reason"}``. ``escalate`` also refuses the call and
records a flag the oversight queue lists; the subject goes on only under a new
signed policy. An error while deciding refuses (fail closed); exit status 0.

Spend reaches the ledger after each step (``tine budget record``), so the step
that crosses a limit completes and the next action is refused: denied within
one step. :class:`BudgetMcpGuard` does the same for ``tools/call`` requests
relayed by ``tine mcp-proxy --budget SUBJECT``, answering a JSON-RPC error.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from typing import IO, Any

PROTOCOL = "opentine-budget/1"
ERROR_CODE = -32002
MAX_PAYLOAD = 8 * 1024 * 1024


def clock_ms() -> int:
    return time.time_ns() // 1_000_000


def decide(repo: Any, subject: str, key: Any, now_ms: int) -> dict[str, Any]:
    """``{"decision", "reason", "over", "flags"}`` for the next action."""
    from opentine._budget_status import check

    try:
        body = check(repo, subject, now_ms=now_ms, key=key)
    except Exception as exc:  # noqa: BLE001 - the gate fails closed
        return {"decision": "deny", "reason": f"budget check failed: {type(exc).__name__}",
                "over": [], "flags": []}  # fmt: skip
    over = body["over"]
    reason = f"budget for {subject} reached: {', '.join(over)}" if over else "within budget"
    return {"decision": body["decision"], "reason": reason, "over": over, "flags": body["flags"]}


def respond(agent: str, decision: dict[str, Any]) -> dict[str, Any]:
    refused = decision["decision"] != "allow"
    reason = f"budget: {decision['reason']}"
    if agent in ("claude-code", "codex"):
        return (
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
            if refused
            else {}
        )
    if agent == "gemini":
        return {"decision": "deny", "reason": reason} if refused else {}
    return {"protocol": PROTOCOL, "decision": decision["decision"], "reason": decision["reason"],
            "over": decision["over"]}  # fmt: skip


def run(args: Any, stream: IO[bytes] | None = None, out: IO[bytes] | None = None,
        now: Callable[[], int] = clock_ms) -> int:  # fmt: skip
    from opentine._key_hygiene import ed25519_private
    from opentine.repo import Repo

    try:
        (stream or sys.stdin.buffer).read(MAX_PAYLOAD + 1)  # the call itself is not needed
    except Exception:  # noqa: BLE001
        pass
    try:
        decision = decide(Repo.open(args.repo), args.subject, ed25519_private(args.key), now())
    except Exception as exc:  # noqa: BLE001 - a hook never crashes the agent; it refuses
        decision = {"decision": "deny", "reason": f"cannot gate: {type(exc).__name__}: {exc}",
                    "over": [], "flags": []}  # fmt: skip
    sink = out or sys.stdout.buffer
    sink.write(json.dumps(respond(args.agent or "generic", decision), sort_keys=True).encode()
               + b"\n")  # fmt: skip
    sink.flush()
    return 0


class BudgetMcpGuard:
    """A ``tools/call`` guard for the MCP proxy; *inner* (a monitor guard) runs after it."""

    advisory = False

    def __init__(self, repo: Any, subject: str, key: Any, inner: Any = None,
                 now: Callable[[], int] = clock_ms) -> None:  # fmt: skip
        self.repo, self.subject, self.key, self.inner, self.now = repo, subject, key, inner, now
        self.denied = 0

    def close(self) -> None:
        if self.inner is not None:
            self.inner.close()

    def _pass(self, raw: bytes) -> tuple[bytes | None, bytes | None, bytes | None]:
        return self.inner.check(raw) if self.inner is not None else (raw, None, None)

    def check(self, raw: bytes) -> tuple[bytes | None, bytes | None, bytes | None]:
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return self._pass(raw)
        items = message if isinstance(message, list) else [message]
        calls = [i for i in items if isinstance(i, dict) and i.get("method") == "tools/call"]
        if not calls:
            return self._pass(raw)
        decision = decide(self.repo, self.subject, self.key, self.now())
        if decision["decision"] == "allow":
            return self._pass(raw)
        self.denied += len(calls)
        rest = [i for i in items if i not in calls]
        data = {"opentine.budget": {"decision": decision["decision"], "over": decision["over"]}}
        replies = [{"jsonrpc": "2.0", "id": c["id"], "error": {
            "code": ERROR_CODE, "message": f"refused by budget: {decision['reason']}",
            "data": data}} for c in calls if "id" in c]  # fmt: skip
        batch = isinstance(message, list)
        end = b"\n" if raw.endswith(b"\n") else b""

        def line(value: Any) -> bytes:
            return json.dumps(value, separators=(",", ":"), sort_keys=True).encode() + end

        forward = None
        if rest:
            forward = self._pass(line(rest if batch else rest[0]))[0]
        back = line(replies if batch else replies[0]) if replies else None
        return forward, back, raw


__all__ = ["BudgetMcpGuard", "ERROR_CODE", "PROTOCOL", "decide", "respond", "run"]
