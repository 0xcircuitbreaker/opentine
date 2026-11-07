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
  response, and for Claude Code the ``Stop`` hook's ``{"decision": "block",
  "reason": TEXT}``, which makes the agent continue with the message as its
  next instruction. Other vendor CLIs get the steer recorded but not injected.
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


def vendor_response(agent: str, response: dict[str, Any]) -> dict[str, Any]:
    """What a vendor CLI reads on stdout: only Claude Code's block carries a steer."""
    steer = response.get("steer") or []
    if agent == "claude-code":
        if steer:
            return {"decision": "block", "reason": "\n\n".join(steer)}
        return {"suppressOutput": True}
    return {}


__all__ = ["STEER_KEY", "deliver_mail", "steer_steps", "vendor_response"]
