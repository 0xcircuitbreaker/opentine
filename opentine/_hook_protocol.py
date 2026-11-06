"""``tine hook capture``: the generic per-turn hook protocol, ``opentine-hook/1``.

One JSON object arrives on **stdin**; one JSON object leaves on **stdout**. The
generic form is::

    {"protocol": "opentine-hook/1", "event": "prompt|tool|turn_end|session_end",
     "session": "<id>", "prompt": "...", "tool": {"name", "input", "output"},
     "message": "...", "cwd": "..."}

Vendor payloads are accepted as they are (``hook_event_name`` plus
``session_id``, ``prompt``, ``tool_name``/``tool_input``/``tool_response``):
Claude Code and Codex ``UserPromptSubmit``/``PostToolUse``/``Stop``/
``SessionEnd``, Gemini CLI ``BeforeAgent``/``AfterTool``/``AfterAgent``/
``SessionEnd`` (see :data:`EVENTS`). So each agent's config is a thin shim
that runs this one command.

Every session is one run on ``heads/capture/<agent>/<digest of session id>``.
Each event becomes one step and is **durable before the command returns**: the
event object is written and the ref (fsynced) advanced to a run that lists it.
A session killed mid-way therefore leaves a ``running`` run holding every step
that finished. ``session_end`` marks it ``completed``.

Capture is off unless the repository's *trusted* porcelain config sets
``hooks.capture`` (``tine enable`` does): an untrusted, cloned ``.tine`` never
turns it on (``_porcelain_config`` pins trust to the config and hook digests).
A hook must never break the agent: every failure still exits 0.

``turn_end`` runs the callbacks in :mod:`opentine._hook_turns` (the per-turn
workspace snapshot point) and stores what they return on that step.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path
from typing import IO, Any

PROTOCOL = "opentine-hook/1"
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
LOCK_WAIT = 10.0
STALE_LOCK = 60.0
KINDS = ("prompt", "tool", "turn_end", "session_end")
#: Vendor event name -> protocol event (Claude Code, Codex, Gemini CLI).
EVENTS = {
    "UserPromptSubmit": "prompt",
    "BeforeAgent": "prompt",
    "PostToolUse": "tool",
    "AfterTool": "tool",
    "Stop": "turn_end",
    "AfterAgent": "turn_end",
    "SessionEnd": "session_end",
}
_AGENT = re.compile(r"[^a-z0-9-]")


def normalize(payload: Any) -> dict[str, Any] | None:
    """The protocol form of one payload (generic or vendor), or ``None``."""
    if not isinstance(payload, dict):
        return None
    kind = payload.get("event") if payload.get("protocol") == PROTOCOL else None
    kind = kind or EVENTS.get(str(payload.get("hook_event_name", "")))
    session = payload.get("session") or payload.get("session_id")
    if kind not in KINDS or not isinstance(session, str) or not session:
        return None
    tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else {}
    message = payload.get("message", payload.get("last_assistant_message"))
    return {
        "event": kind,
        "session": session[:512],
        "prompt": payload.get("prompt"),
        "tool": {
            "name": str(tool.get("name") or payload.get("tool_name") or "")[:256],
            "input": tool.get("input", payload.get("tool_input")),
            "output": tool.get("output", payload.get("tool_response")),
        },
        "message": message,
        "cwd": payload.get("cwd") if isinstance(payload.get("cwd"), str) else "",
    }


def session_ref(agent: str, session: str) -> str:
    name = _AGENT.sub("-", agent.lower())[:40] or "generic"
    return f"heads/capture/{name}/{hashlib.sha256(session.encode()).hexdigest()[:32]}"


def enabled(repo_path: Path) -> bool:
    from opentine import _porcelain_config as porcelain

    value = porcelain.effective(repo_path).get("hooks.capture", "")
    return str(value).lower() in ("1", "true", "yes", "on")


class _Lock:
    """One writer per session ref: concurrent hooks append in turn, never lose one."""

    def __init__(self, path: Path):
        self.path = path

    def __enter__(self) -> _Lock:
        deadline = time.monotonic() + LOCK_WAIT
        while True:
            try:
                os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
                return self
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > STALE_LOCK:
                        self.path.unlink(missing_ok=True)  # its writer died
                        continue
                except OSError:
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError(f"{self.path.name} is held") from None
                time.sleep(0.02)

    def __exit__(self, *exc: object) -> None:
        self.path.unlink(missing_ok=True)


def _step(event: dict[str, Any], agent: str, extra: dict[str, Any]):
    from opentine.trace.schema import TraceEvent

    kind, tool = event["event"], event["tool"]
    inputs: dict[str, Any] = {}
    outputs: dict[str, Any] = {}
    step_kind, actor = "human", "user"
    if kind == "prompt":
        inputs = {"prompt": event["prompt"]}
    elif kind == "tool":
        step_kind, actor = "tool", tool["name"] or "tool"
        inputs, outputs = {"input": tool["input"]}, {"output": tool["output"]}
    else:
        step_kind, actor = "model", agent
        outputs = {"message": event["message"]} if event["message"] is not None else {}
        if isinstance(tree := extra.get("opentine.snapshot.tree"), str):
            outputs["tree"] = tree  # what ``tine rewind --tree`` reads
    attributes = {"opentine.hook.protocol": PROTOCOL, "opentine.hook.event": kind,
                  "opentine.hook.agent": agent, **extra}  # fmt: skip
    return TraceEvent(
        kind=step_kind,
        timestamp=time.time(),
        trace_id=hashlib.sha256(event["session"].encode()).hexdigest()[:32],
        span_id=secrets.token_hex(8),
        actor=actor,
        inputs=json.loads(json.dumps(inputs, default=str)),
        outputs=json.loads(json.dumps(outputs, default=str)),
        attributes=attributes,
    )


def record(repo: Any, event: dict[str, Any], agent: str) -> dict[str, Any]:
    """Append *event* to its session's run, durably; the protocol response."""
    from opentine import _hook_turns
    from opentine.repository._paths import internal_path
    from opentine.trace.recorder import Recorder

    ref = session_ref(agent, event["session"])
    with _Lock(internal_path(Path(repo.path), f"capture-{ref.rsplit('/', 1)[1]}.lock")):
        try:
            existing = repo.read_ref(ref)
        except ValueError:
            existing = None
        if existing:
            recorder = Recorder.resume(repo, ref, ref=ref)
        else:
            recorder = Recorder.start(repo, ref=ref, capture=False)
        extra: dict[str, Any] = {}
        if event["event"] == "turn_end":
            extra = _hook_turns.run_turn_end(repo, recorder, event, agent)
        if event["event"] != "session_end" or event["message"] is not None:
            recorder.append(_step(event, agent, extra))
        if event["event"] == "session_end":
            recorder.finalize("completed")
        steps = len(recorder.payload.get("events") or [])
    return {"protocol": PROTOCOL, "ok": True, "event": event["event"], "ref": ref,
            "run": recorder.run_id, "steps": steps}  # fmt: skip


def handle(raw: bytes, repo_path: str | None, agent: str) -> dict[str, Any]:
    """Process one stdin payload; never raises."""
    try:
        if len(raw) > MAX_PAYLOAD_BYTES:
            return {"protocol": PROTOCOL, "ok": False, "reason": "payload too large"}
        event = normalize(json.loads(raw.decode("utf-8")))
        if event is None:
            return {"protocol": PROTOCOL, "ok": False, "reason": "not a capture event"}
        if not repo_path:
            return {"protocol": PROTOCOL, "ok": False, "reason": "no --repo"}
        from opentine.repo import Repo

        repo = Repo.open(Path(repo_path))
        if not enabled(Path(repo.path)):
            return {"protocol": PROTOCOL, "ok": False, "reason": "capture is not enabled"}
        return record(repo, event, agent)
    except Exception as exc:  # noqa: BLE001 - a hook must never fail the session
        return {"protocol": PROTOCOL, "ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def run_capture(
    repo_path: str | None, agent: str | None, stream: IO[bytes] | None = None,
    out: IO[str] | None = None,
) -> int:  # fmt: skip
    """``tine hook capture``: read stdin, write the response; always 0."""
    try:
        raw = (stream or sys.stdin.buffer).read(MAX_PAYLOAD_BYTES + 1)
    except Exception:  # noqa: BLE001
        raw = b""
    response = handle(raw, repo_path, agent or "generic")
    if agent and agent != "generic":
        # A vendor CLI parses stdout as its own control JSON: say nothing it acts on.
        response = {"suppressOutput": True} if agent == "claude-code" else {}
    try:
        (out or sys.stdout).write(json.dumps(response, sort_keys=True) + "\n")
        (out or sys.stdout).flush()
    except Exception:  # noqa: BLE001
        pass
    return 0


__all__ = ["EVENTS", "KINDS", "PROTOCOL", "enabled", "handle", "normalize", "record",
           "run_capture", "session_ref"]  # fmt: skip
