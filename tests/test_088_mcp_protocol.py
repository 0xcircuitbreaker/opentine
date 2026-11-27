"""0.88: the own MCP server speaks 2026-07-28 and keeps 2025-11-25, with no silent downgrade."""

from __future__ import annotations

import asyncio

import pytest

from opentine._mcp_protocol import (
    HANDSHAKE,
    MODERN,
    UNSUPPORTED_PROTOCOL_VERSION,
    handshake_version,
    sdk_window,
)


def test_the_handshake_window_never_answers_a_newer_ask_with_an_older_version():
    assert handshake_version(HANDSHAKE) == HANDSHAKE
    assert handshake_version("2025-06-18") == HANDSHAKE  # the client sees it and may decline
    assert handshake_version(MODERN) is None and handshake_version("2099-01-01") is None
    assert handshake_version(None) is None


@pytest.fixture
def server(tmp_path, monkeypatch):
    pytest.importorskip("mcp.server.mcpserver")
    from opentine import mcp_server

    monkeypatch.chdir(tmp_path)
    return mcp_server.create_server(read_only=True)


def test_a_modern_client_negotiates_2026_07_28(server):
    from mcp import Client

    from opentine._version import __version__

    assert sdk_window() == (MODERN, HANDSHAKE)

    async def scenario():
        async with Client(server) as client:
            listed = await client.list_tools()
            return client.session.protocol_version, listed.meta

    version, meta = asyncio.run(scenario())
    assert version == MODERN
    assert meta["io.modelcontextprotocol/serverInfo"] == {"name": "opentine",
                                                          "version": __version__}  # fmt: skip


def test_a_legacy_client_keeps_2025_11_25_and_a_newer_handshake_is_refused(server):
    from mcp import Client
    from mcp.shared.exceptions import MCPError

    hello = {"capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}

    async def scenario():
        async with Client(server, mode="legacy") as client:
            raw = client.session._dispatcher.send_raw_request
            old = await raw("initialize", {**hello, "protocolVersion": "2025-06-18"}, {})
            refused = []
            for ask in (MODERN, "2099-01-01"):
                with pytest.raises(MCPError) as exc:
                    await raw("initialize", {**hello, "protocolVersion": ask}, {})
                refused.append(exc.value)
            return client.session.protocol_version, old, refused

    version, old, refused = asyncio.run(scenario())
    assert version == HANDSHAKE and old["protocolVersion"] == HANDSHAKE
    for error in refused:
        assert error.error.code == UNSUPPORTED_PROTOCOL_VERSION
        assert error.error.data["supported"] == [MODERN, HANDSHAKE]
