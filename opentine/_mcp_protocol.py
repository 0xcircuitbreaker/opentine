"""The MCP protocol versions ``python -m opentine.mcp_server`` speaks (0.88).

The support window is :data:`WINDOW`: MCP 2026-07-28, negotiated per request
(``server/discover`` and the request ``_meta`` protocol version, SDK 2.x), and
2025-11-25 through the ``initialize`` handshake, kept for existing clients
(MCP tasks stay a 2025-11-25 feature, :mod:`opentine._mcp_tasks`).

There is no silent downgrade. The SDK answers an ``initialize`` that asks for a
version newer than its newest handshake version with that older version; this
server refuses such a request instead (JSON-RPC error
:data:`UNSUPPORTED_PROTOCOL_VERSION`, with the supported versions in ``data``),
so a client that can speak 2026-07-28 learns to negotiate it rather than
quietly running on 2025-11-25. An ``initialize`` for an older handshake version
is answered with 2025-11-25, which the client sees and may decline. A request
for an unsupported per-request version is refused by the SDK itself.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

MODERN = "2026-07-28"
HANDSHAKE = "2025-11-25"
WINDOW = (MODERN, HANDSHAKE)
UNSUPPORTED_PROTOCOL_VERSION = -32022


def sdk_window() -> tuple[str, ...]:
    """The versions of :data:`WINDOW` the installed SDK can negotiate."""
    try:
        from mcp.shared.inbound import MODERN_PROTOCOL_VERSIONS
    except ImportError:  # SDK 1.x: the handshake only
        return (HANDSHAKE,)
    return tuple(v for v in WINDOW if v == HANDSHAKE or v in MODERN_PROTOCOL_VERSIONS)


def handshake_version(requested: Any) -> str | None:
    """The version an ``initialize`` asking *requested* gets, ``None``: refused."""
    if not isinstance(requested, str) or requested > HANDSHAKE:
        return None
    return HANDSHAKE


class ProtocolWindow:
    """Server middleware enforcing :data:`WINDOW` on ``initialize``."""

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        if ctx.method != "initialize":
            return await call_next(ctx)
        params = ctx.params if isinstance(ctx.params, dict) else {}
        requested = params.get("protocolVersion")
        answer = handshake_version(requested)
        if answer is None:
            from mcp.shared.exceptions import MCPError

            supported = list(sdk_window())
            raise MCPError(UNSUPPORTED_PROTOCOL_VERSION,
                           f"initialize negotiates {HANDSHAKE} only; {MODERN} is negotiated "
                           "per request", {"supported": supported,
                                           "requested": str(requested)[:64]})  # fmt: skip
        if requested != answer:
            ctx = replace(ctx, params={**params, "protocolVersion": answer})
        return await call_next(ctx)


def install(server: Any) -> Any:
    """Put :class:`ProtocolWindow` first on an SDK 2.x *server*; 1.x has no middleware."""
    middleware = getattr(server, "middleware", None)
    if isinstance(middleware, list):
        middleware.insert(0, ProtocolWindow())
    return server


__all__ = [
    "HANDSHAKE",
    "MODERN",
    "UNSUPPORTED_PROTOCOL_VERSION",
    "WINDOW",
    "ProtocolWindow",
    "handshake_version",
    "install",
    "sdk_window",
]
