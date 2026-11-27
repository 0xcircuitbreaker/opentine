"""``tine mcp-proxy --tool-defs block``: refuse calls to a changed tool definition (0.88).

The default, ``advisory``, only records (:mod:`opentine._mcp_tool_pins`, D12: it
never blocks). ``block`` (stdio only) adds this guard as the outermost one: it
sees every ``tools/list`` answer before a byte of it reaches the client
(:meth:`ToolDefGuard.observe`, called by the relay), keeps its own pin, and
answers a ``tools/call`` with JSON-RPC error :data:`ERROR_CODE` instead of
forwarding it when the tool's definition differs from the session pin, the
tool was never listed, or nothing was listed yet (fail closed).
"""

from __future__ import annotations

import json
from typing import Any

from opentine._mcp_tool_pins import UNPINNED, ToolPins, loads

ERROR_CODE = -32004
MODES = ("advisory", "block")
MAX_PENDING = 4096


class ToolDefGuard:
    advisory = False

    def __init__(self, inner: Any = None) -> None:
        self.inner, self.pins, self.refused = inner, ToolPins(), 0
        self._lists: dict[str, Any] = {}

    @property
    def denied(self) -> int:  # the budget guard's count, which the CLI reports
        return getattr(self.inner, "denied", 0)

    def close(self) -> None:
        if self.inner is not None:
            self.inner.close()

    def _pass(self, raw: bytes) -> tuple[bytes | None, bytes | None, bytes | None]:
        return self.inner.check(raw) if self.inner is not None else (raw, None, None)

    def observe(self, raw: bytes) -> None:
        """A server line: pin the answers to the client's ``tools/list`` requests."""
        try:
            message = loads(raw)
        except (UnicodeDecodeError, ValueError, RecursionError):
            return
        for item in message if isinstance(message, list) else [message]:
            if isinstance(item, dict) and "id" in item and "method" not in item:
                key = json.dumps(item["id"], sort_keys=True)
                if key in self._lists and isinstance(item.get("result"), dict):
                    self.pins.listed(self._lists.pop(key), item["result"])

    def _refusal(self, item: dict[str, Any]) -> str | None:
        params = item.get("params") if isinstance(item.get("params"), dict) else {}
        digest, code = self.pins.call(params.get("name"))
        return code or (UNPINNED if digest is None else None)

    def check(self, raw: bytes) -> tuple[bytes | None, bytes | None, bytes | None]:
        try:
            message = loads(raw)
        except (UnicodeDecodeError, ValueError, RecursionError):
            return self._pass(raw)
        items = [i for i in (message if isinstance(message, list) else [message])
                 if isinstance(i, dict)]  # fmt: skip
        for item in items:
            if item.get("method") == "tools/list" and "id" in item:
                self._lists[json.dumps(item["id"], sort_keys=True)] = item.get("params")
                while len(self._lists) > MAX_PENDING:
                    self._lists.pop(next(iter(self._lists)))
        refused = [(i, c) for i in items if i.get("method") == "tools/call"
                   if (c := self._refusal(i)) is not None]  # fmt: skip
        if not refused:
            return self._pass(raw)
        self.refused += len(refused)
        gone = [i for i, _ in refused]
        rest = [i for i in items if not any(i is g for g in gone)]
        replies = [{"jsonrpc": "2.0", "id": i["id"], "error": {
            "code": ERROR_CODE, "message": f"refused: {code} (the tool definition is not the "
            "one pinned at session start)", "data": {"opentine.tool-def": {"code": code}}}}
            for i, code in refused if "id" in i]  # fmt: skip
        batch = isinstance(message, list)
        end = b"\n" if raw.endswith(b"\n") else b""

        def line(value: Any) -> bytes:
            return json.dumps(value, separators=(",", ":"), sort_keys=True).encode() + end

        forward = self._pass(line(rest if batch else rest[0]))[0] if rest else None
        back = line(replies if batch else replies[0]) if replies else None
        return forward, back, raw


def wrap(mode: str | None, guard: Any, http: bool) -> Any:
    """The guard chain for ``--tool-defs MODE``; ``ValueError`` for block over HTTP."""
    if mode in (None, "advisory"):
        return guard
    if mode != "block":
        raise ValueError(f"--tool-defs is one of {', '.join(MODES)}")
    if http:
        raise ValueError("--tool-defs block needs the stdio transport")
    return ToolDefGuard(guard)


def cli_wrap(args: Any, guard: Any) -> Any:
    """:func:`wrap` for ``tine mcp-proxy``: a bad combination is a usage error."""
    from opentine._cli_errors import fail

    try:
        return wrap(getattr(args, "tool_defs", None), guard, bool(args.http_upstream))
    except ValueError as exc:
        fail(str(exc), prefix="mcp-proxy")


__all__ = ["ERROR_CODE", "MODES", "ToolDefGuard", "cli_wrap", "wrap"]
