"""The model-organism gate (0.72): refuse loading a tagged artifact without approval.

:func:`decide` takes one tool call (``{"name", "arguments"}``) and the requesting
run. A call references a tagged artifact when any string in its arguments
(or any whitespace-, quote- or ``=``-separated word of one) holds the
artifact's 64-hex digest, or equals or ends with ``/NAME`` for a name its tag
recorded. Such a call is allowed only with a valid approval record bound to
that artifact *and* that run (:mod:`opentine._organism`); allowed or not, every
access is logged and held. A registry that cannot be read refuses every call
(fail closed). Renamed or re-encoded copies are not detected here: weights are
matched by digest and recorded names, not hashed on each call.

Two transports use it: ``tine organism gate`` on the agent hook path (the
payload shapes and responses of ``tine monitor gate``,
:mod:`opentine._monitor_hook`), and :class:`OrganismMcpGuard` in ``tine
mcp-proxy --organism-gate``.
"""

from __future__ import annotations

import json
import re
import sys
from typing import IO, Any

from opentine._organism import now
from opentine._organism_registry import (
    RegistryUnreadable,
    approval_for,
    log_access,
    registry,
)

ERROR_CODE = -32003
_SPLIT = re.compile(r"[\s\"'=,;()\[\]{}<>]+")


def _strings(value: Any) -> list[str]:
    from opentine._holdout_touch import _strings as leaves

    out = []
    for text in leaves(value):
        norm = text.replace("\\", "/")
        out.append(norm)
        out.extend(w for w in _SPLIT.split(norm) if w and w != norm)
    return out


def _hits(entry: dict[str, Any], artifact: str, words: list[str]) -> bool:
    hexd = artifact.removeprefix("sha256:")
    for word in words:
        if hexd in word.lower():
            return True
        for name in entry["names"]:
            if word == name or word.endswith("/" + name.lstrip("/")):
                return True
    return False


def referenced(tags: dict[str, dict[str, Any]], params: Any) -> list[str]:
    """The tagged artifacts a tool call's name or arguments reference."""
    words = _strings(params if isinstance(params, (dict, list)) else [params])
    return sorted(a for a, e in tags.items() if e["tagged"] and _hits(e, a, words))


def decide(repo: Any, params: Any, run: str, at: str | None = None) -> dict[str, Any]:
    """``{"outcome": "forward"|"block", "reason", "artifacts", "logged"}``."""
    try:
        if repo is None:
            raise RegistryUnreadable("organism.registry-unreadable: no repository")
        found = referenced(registry(repo), params)
    except Exception as exc:  # noqa: BLE001 - an unreadable registry refuses (fail closed)
        return {"outcome": "block", "artifacts": [], "logged": [],
                "reason": f"model-organism registry unreadable: {exc}"}  # fmt: skip
    if not found:
        return {"outcome": "forward", "artifacts": [], "logged": [], "reason": ""}
    tool = params.get("name") if isinstance(params, dict) else None
    refused, logged = [], []
    for artifact in found:
        approval = approval_for(repo, artifact, run)
        outcome = "allowed" if approval else "refused"
        if approval is None:
            refused.append(artifact)
        logged.append(log_access(repo, {"artifact": artifact, "run": run, "outcome": outcome,
                                        "tool": tool if isinstance(tool, str) else None,
                                        "approval": approval, "at": at or now()}))  # fmt: skip
    if refused:
        return {"outcome": "block", "artifacts": found, "logged": logged,
                "reason": f"tagged model organism {', '.join(refused)} needs an approval "
                          f"bound to run {run!r} (tine organism approve)"}  # fmt: skip
    return {"outcome": "forward", "artifacts": found, "logged": logged, "reason": ""}


def hook(raw: bytes, args: Any) -> dict[str, Any]:
    from opentine._monitor_hook import MAX_PAYLOAD, normalize
    from opentine.repo import Repo

    try:
        if len(raw) > MAX_PAYLOAD:
            raise ValueError("payload too large")
        payload = json.loads(raw.decode("utf-8"))
        event = normalize(payload)
    except Exception as exc:  # noqa: BLE001 - D12: an unreadable payload proceeds by default
        return {"outcome": "block" if args.fail_closed else "forward", "artifacts": [],
                "logged": [], "reason": f"cannot gate: {type(exc).__name__}: {exc}"}  # fmt: skip
    run = args.run or str(payload.get("run") or event["session"])
    try:
        repo = Repo.open(args.repo)
    except Exception:  # noqa: BLE001 - no repository: the registry is unreadable
        repo = None
    return decide(repo, event["params"], run)


def run(args: Any, stream: IO[bytes] | None = None, out: IO[bytes] | None = None) -> int:
    from opentine._monitor_hook import MAX_PAYLOAD, respond

    try:
        raw = (stream or sys.stdin.buffer).read(MAX_PAYLOAD + 1)
    except Exception:  # noqa: BLE001
        raw = b""
    decision = hook(raw, args)
    body = respond(args.agent or "generic", {**decision, "verdict": None, "replacement": None})
    text = json.dumps(body, sort_keys=True).replace("monitor: ", "organism: ")
    sink = out or sys.stdout.buffer
    sink.write(text.encode("utf-8") + b"\n")
    sink.flush()
    return 0


class OrganismMcpGuard:
    """A ``tools/call`` guard for the MCP proxy; *inner* runs on what it lets through."""

    advisory = False

    def __init__(self, repo: Any, run: str, inner: Any = None) -> None:
        self.repo, self.run, self.inner, self.denied = repo, run, inner, 0

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
        rest, replies, blocked = [], [], []
        for msg in items:
            if not (isinstance(msg, dict) and msg.get("method") == "tools/call"):
                rest.append(msg)
                continue
            decision = decide(self.repo, msg.get("params"), self.run)
            if decision["outcome"] == "forward":
                rest.append(msg)
                continue
            self.denied += 1
            blocked.append(msg)
            if "id" in msg:
                data = {"opentine.organism": {"artifacts": decision["artifacts"]}}
                replies.append({"jsonrpc": "2.0", "id": msg["id"], "error": {
                    "code": ERROR_CODE, "message": f"refused: {decision['reason']}",
                    "data": data}})  # fmt: skip
        if not blocked:
            return self._pass(raw)
        batch, end = isinstance(message, list), b"\n" if raw.endswith(b"\n") else b""

        def line(value: Any) -> bytes:
            return json.dumps(value, separators=(",", ":"), sort_keys=True).encode() + end

        forward = self._pass(line(rest if batch else rest[0]))[0] if rest else None
        back = line(replies if batch else replies[0]) if replies else None
        return forward, back, raw


__all__ = ["ERROR_CODE", "OrganismMcpGuard", "decide", "hook", "referenced", "run"]
