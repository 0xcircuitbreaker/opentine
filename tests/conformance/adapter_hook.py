"""Reference ops for SPEC 8.16: the ``opentine-hook/1`` event envelope and vendor answers."""

from __future__ import annotations

from typing import Any

from opentine._hook_mailbox import vendor_response
from opentine._hook_protocol import normalize


def op_hook_normalize(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    hint = value.get("hint")
    event = normalize(value.get("payload"), hint if isinstance(hint, str) else None)
    if event is None:
        return {"ok": False, "event": None, "session": None, "tool_name": None, "cwd": None}
    return {"ok": True, "event": event["event"], "session": event["session"],
            "tool_name": event["tool"]["name"], "cwd": event["cwd"]}  # fmt: skip


def op_hook_respond(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    return {"stdout": vendor_response(value["agent"], {"steer": list(value["steer"])})}


OPS = {"hook.normalize": op_hook_normalize, "hook.respond": op_hook_respond}
