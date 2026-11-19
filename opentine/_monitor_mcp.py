"""The gate inside ``tine mcp-proxy`` (0.63): JSON-RPC ``tools/call`` in, a decision out.

:class:`McpGuard` sits on the client-to-server direction of both transports.
For one client message it returns ``(forward, reply, blocked)``: the bytes to
relay to the server, the bytes to answer the client with, and the blocked
requests themselves (each ``None`` when there is nothing), so the recorder
keeps the blocked request next to its error. Only ``tools/call`` requests are gated.

* advisory mode relays every byte unchanged at once and scores the calls on a
  worker thread afterwards (a full queue drops the verdict and counts it);
* gate mode decides before relaying: a blocked call is answered with a
  JSON-RPC error whose ``data`` carries ``{"opentine.monitor": {"verdict",
  "action", "outcome"}}`` and is never relayed; a replaced call is relayed as
  the alternate, whose ``params._meta["opentine/monitor"]`` names the verdict.
  An exception while deciding blocks (fail closed) with ``verdict: null``,
  which ``tine monitor verify`` reports.
"""

from __future__ import annotations

import json
import queue
import threading
from typing import Any

from opentine._monitor_gate import Gate
from opentine._monitor_verdict import META_KEY

ERROR_CODE = -32001
MAX_ADVISORY_QUEUE = 1024


def blocked_reply(ident: Any, decision: dict[str, Any]) -> dict[str, Any]:
    claim = decision.get("claim") or {}
    data = {"verdict": decision.get("verdict"), "action": claim.get("action", "block"),
            "outcome": "block"}  # fmt: skip
    return {"jsonrpc": "2.0", "id": ident, "error": {
        "code": ERROR_CODE, "message": f"blocked by monitor: {decision.get('reason', '')}",
        "data": {"opentine.monitor": data}}}  # fmt: skip


def _gated(item: Any) -> bool:
    """A ``tools/call`` request or notification (a server may run either)."""
    return isinstance(item, dict) and item.get("method") == "tools/call"


def _strict(raw: bytes) -> Any:
    """Parse as a server would, refusing what parsers read differently (duplicate keys, NaN)."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({k for k, _ in items}) != len(items):
            raise ValueError("duplicate key")
        return dict(items)

    def constant(name: str) -> Any:
        raise ValueError(f"non-standard constant {name}")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def _unmark(item: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """*item* without a client-supplied replacement mark (only the gate writes one)."""
    params = item.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    if not isinstance(meta, dict) or META_KEY not in meta:
        return item, False
    rest = {k: v for k, v in meta.items() if k != META_KEY}
    params = {**params, "_meta": rest} if rest else {
        k: v for k, v in params.items() if k != "_meta"}  # fmt: skip
    return {**item, "params": params}, True


class McpGuard:
    def __init__(self, gate: Gate, report: Any = lambda message: None) -> None:
        self.gate, self.report = gate, report
        self.advisory = gate.config["mode"] != "gate"
        self.dropped = 0
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(MAX_ADVISORY_QUEUE)
        self._worker: threading.Thread | None = None
        if self.advisory:
            self._worker = threading.Thread(target=self._drain, daemon=True)
            self._worker.start()

    def _drain(self) -> None:
        while (item := self._queue.get()) is not None:
            try:
                self.gate.decide("tools/call", item.get("params"))
            except Exception as exc:  # noqa: BLE001 - advisory never breaks the session
                self.report(f"mcp-proxy: monitor failed: {type(exc).__name__}: {exc}")

    def close(self) -> None:
        if self._worker is not None:
            self._queue.put(None)
            self._worker.join(timeout=600)

    def _decide(self, item: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.gate.decide("tools/call", item.get("params"))
        except Exception as exc:  # noqa: BLE001 - gate mode fails closed
            self.report(f"mcp-proxy: monitor failed, blocking: {type(exc).__name__}: {exc}")
            return {
                "outcome": "block",
                "verdict": None,
                "claim": None,
                "replacement": None,
                "reason": f"monitor failed: {type(exc).__name__}",
            }

    def check(self, raw: bytes) -> tuple[bytes | None, bytes | None, bytes | None]:
        """``(bytes to relay, bytes to answer the client, blocked requests)``."""
        try:
            message = _strict(raw) if not self.advisory else json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            if self.advisory or not raw.strip():
                return raw, None, None  # advisory relays every byte
            self.report("mcp-proxy: a client message the gate cannot parse was dropped")
            return None, None, None
        items = message if isinstance(message, list) else [message]
        if not any(_gated(item) for item in items):
            return raw, None, None
        if self.advisory:
            for item in filter(_gated, items):
                try:
                    self._queue.put_nowait(item)
                except queue.Full:
                    self.dropped += 1
            return raw, None, None
        forward, replies, blocked, changed = [], [], [], False
        for item in items:
            if not _gated(item):
                forward.append(item)
                continue
            item, stripped = _unmark(item)
            changed = changed or stripped
            decision = self._decide(item)
            if decision["outcome"] == "block" and "id" not in item:
                self.report("mcp-proxy: a blocked tools/call notification was dropped")
                changed = True
            elif decision["outcome"] == "block":
                replies.append(blocked_reply(item["id"], decision))
                blocked.append(item)
                changed = True
            elif decision["outcome"] == "replace":
                forward.append({**item, "params": decision["replacement"]})
                changed = True
            else:
                forward.append(item)
        if not changed:
            return raw, None, None
        if not forward and not replies:
            return None, None, None
        batch = isinstance(message, list)
        out = _line(forward if batch else forward[0], raw) if forward else None
        back = _line(replies if batch else replies[0], raw) if replies else None
        held = (raw if not batch else _line(blocked, raw)) if blocked else None
        return out, back, held


def _line(value: Any, raw: bytes) -> bytes:
    text = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return text + b"\n" if raw.endswith(b"\n") else text


__all__ = ["ERROR_CODE", "McpGuard", "blocked_reply"]
