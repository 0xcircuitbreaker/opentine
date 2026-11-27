"""MCP tool-definition pinning for ``tine mcp-proxy`` (0.88).

The first complete ``tools/list`` answer of a session (every page, followed by
``nextCursor``) is the session's pin: ``{tool name: tool_def_digest}``. A later
listing whose definitions differ is recorded as a change
(``advisory:mcp.tool-def-changed``); a ``tools/call`` step carries the
``tool_def_digest`` of the definition in force and, when that differs from the
pin or the tool was never listed, the advisory code. With ``--tool-defs block``
such a call is refused with a JSON-RPC error instead of reaching the server.

``tool_def_digest`` is ``sha256:`` over a domain tag and a canonical, lossless
spelling of the definition exactly as the server sent it: keys sorted, no
whitespace, ASCII escapes, numbers as parsed (``1`` and ``1.0`` stay distinct).
An object with duplicate keys keeps every pair in its original order, so it
never hashes like any duplicate-free definition. The digest is computed before
redaction; ``redacted`` lists tools whose recorded definition the credential
scrubber changed (their digest cannot be recomputed from the recording).
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

DOMAIN = b"opentine.mcp-tool-def.v1\0"
CHANGED = "advisory:mcp.tool-def-changed"
UNPINNED = "advisory:mcp.tool-unpinned"
MAX_TOOLS = 4096


class _Dup(dict):
    """An object parsed with duplicate keys: the last value wins, ``pairs`` keeps all."""

    pairs: list[tuple[str, Any]]


def _hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({k for k, _ in pairs}) == len(pairs):
        return dict(pairs)
    found = _Dup(pairs)
    found.pairs = list(pairs)
    return found


def loads(raw: bytes) -> Any:
    """JSON with duplicate keys kept (:class:`_Dup`), for lossless digests."""
    from opentine import _json_shallow

    return _json_shallow.loads(raw, object_pairs_hook=_hook)


def _canon(value: Any) -> str:
    parts: list[str] = []
    if isinstance(value, dict):
        items = value.pairs if isinstance(value, _Dup) else sorted(value.items())
        for key, item in items:  # a loop, not a comprehension: one frame per level
            parts.append(json.dumps(key) + ":" + _canon(item))
        return "{" + ",".join(parts) + "}"
    if isinstance(value, list):
        for item in value:
            parts.append(_canon(item))
        return "[" + ",".join(parts) + "]"
    return json.dumps(value, ensure_ascii=True, allow_nan=True)


def canonical(definition: Any) -> bytes:
    return _canon(definition).encode("ascii")


def tool_def_digest(definition: Any) -> str:
    return "sha256:" + hashlib.sha256(DOMAIN + canonical(definition)).hexdigest()


class ToolPins:
    """The session pin and the definitions in force; thread-safe."""

    def __init__(self) -> None:
        self.pinned: dict[str, str] | None = None
        self.current: dict[str, str] = {}
        self.changes: list[dict[str, Any]] = []
        self.redacted: set[str] = set()
        self._page: dict[str, str] = {}
        self._lock = threading.Lock()

    def listed(self, params: Any, result: Any, step: int | None = None) -> list[dict[str, Any]]:
        """Take one ``tools/list`` page; the change rows it completes (``[]`` mid-listing)."""
        params = params if isinstance(params, dict) else {}
        result = result if isinstance(result, dict) else {}
        tools = result.get("tools") if isinstance(result.get("tools"), list) else []
        with self._lock:
            if not params.get("cursor"):
                self._page = {}
            for tool in tools[:MAX_TOOLS]:
                if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                    self._page[tool["name"]] = tool_def_digest(tool)
            if result.get("nextCursor"):
                return []
            listing, self._page = self._page, {}
            self.current = listing
            if self.pinned is None:
                self.pinned = dict(listing)
                return []
            rows = []
            for name in sorted(self.pinned.keys() | listing.keys()):
                was, now = self.pinned.get(name), listing.get(name)
                if was != now:
                    kind = "added" if was is None else "removed" if now is None else "changed"
                    rows.append({"tool": name, "change": kind, "pinned": was, "now": now,
                                 "step": step, "code": CHANGED})  # fmt: skip
            self.changes.extend(rows)
            return rows

    def call(self, name: Any) -> tuple[str | None, str | None]:
        """``(tool_def_digest, advisory code or None)`` for a ``tools/call`` of *name*."""
        with self._lock:
            if self.pinned is None or not isinstance(name, str):
                return None, UNPINNED  # nothing listed yet, or no name: never pinned
            now = self.current.get(name)
            if now is None or name not in self.pinned:
                return now, UNPINNED
            return now, CHANGED if now != self.pinned[name] else None

    def summary(self) -> dict[str, Any]:
        from opentine.kernel import canonical_json

        with self._lock:
            pinned = dict(sorted((self.pinned or {}).items()))
            digest = hashlib.sha256(canonical_json(pinned)).hexdigest() if self.pinned else None
            return {"pinned": pinned, "pinned_sha256": digest, "changes": list(self.changes),
                    "redacted": sorted(self.redacted)}  # fmt: skip


__all__ = ["CHANGED", "DOMAIN", "UNPINNED", "ToolPins", "canonical", "loads", "tool_def_digest"]
