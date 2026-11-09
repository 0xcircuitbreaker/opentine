"""Steering a running fleet member through ``opentine-hook/1`` (0.43).

``tine fleet send`` queues a message in the member's mailbox
(:mod:`opentine.coord._mailbox`). The member's agent runs ``tine hook capture``
at every turn end; that process inherits ``OPENTINE_FLEET_ID`` and
``OPENTINE_FLEET_MEMBER`` from ``tine fleet up``, so the turn callback here
takes the member's pending messages (once, by compare-and-swap) and hands them
back under :data:`STEER_KEY`. The protocol then:

* records each message as its own ``human`` step (actor ``steer``) right after
  the turn's step, so the run shows exactly when the agent was steered; and
* returns them in the hook response: ``"steer": [TEXT, ...]`` in the generic
  response, and in each vendor's own "keep going" answer to its turn-end hook
  (:data:`CONTINUE`), which makes the agent continue with the message as its
  next instruction: Claude Code's and Codex's ``Stop`` take ``{"decision":
  "block", "reason": TEXT}`` (learn.chatgpt.com/docs/hooks: the reason becomes
  a new user prompt), Gemini CLI's ``AfterAgent`` takes ``{"decision": "deny",
  "reason": TEXT}`` (geminicli.com/docs/hooks/reference: the reason is sent as
  a new prompt). Messages are taken once, so a ``stop_hook_active`` re-entry
  never loops. Copilot CLI, Droid and Antigravity get the steer recorded only.

A session that already ended is continued with ``tine hook resume``
(:mod:`opentine._hook_resume`).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Any

from opentine import _hook_turns

STEER_KEY = "opentine.steer"


@_hook_turns.register
def deliver_mail(context: _hook_turns.TurnContext) -> dict[str, Any] | None:
    fleet, member = os.environ.get("OPENTINE_FLEET_ID"), os.environ.get("OPENTINE_FLEET_MEMBER")
    if not fleet or not member:
        return None
    from opentine.coord._mailbox import take

    messages = take(context.repo, fleet, member)
    return {STEER_KEY: messages} if messages else None


def steer_steps(session: str, messages: list[dict[str, Any]] | None) -> list[Any]:
    """One ``human`` step per delivered message (from :data:`STEER_KEY`)."""
    from opentine.trace.schema import TraceEvent

    steps = []
    for message in messages if isinstance(messages, list) else []:
        steps.append(
            TraceEvent(
                kind="human",
                timestamp=time.time(),
                trace_id=hashlib.sha256(session.encode()).hexdigest()[:32],
                span_id=secrets.token_hex(8),
                actor="steer",
                inputs={"prompt": message["text"]},
                outputs={},
                attributes={
                    "opentine.hook.event": "steer",
                    "opentine.steer.id": message["id"],
                    "opentine.steer.from": message["from"],
                    "opentine.steer.sent_ms": message["sent_ms"],
                },  # fmt: skip
            )
        )
    return steps


#: Agent -> the turn-end decision that continues the agent with ``reason`` as its prompt.
CONTINUE = {"claude-code": "block", "codex": "block", "gemini": "deny"}


def vendor_response(agent: str, response: dict[str, Any]) -> dict[str, Any]:
    """What a vendor CLI reads on stdout: a steer only where :data:`CONTINUE` names one."""
    steer = response.get("steer") or []
    if steer and agent in CONTINUE:
        return {"decision": CONTINUE[agent], "reason": "\n\n".join(steer)}
    return {"suppressOutput": True} if agent == "claude-code" else {}


__all__ = ["CONTINUE", "STEER_KEY", "deliver_mail", "steer_steps", "vendor_response"]
