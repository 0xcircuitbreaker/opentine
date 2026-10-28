"""``python -m opentine.mcp_server --read-only``: an MCP server that cannot write.

The Claude Code plugin (``tine plugin export``) points its ``.mcp.json`` here.
Registration goes through an **allowlist** of tools that only read -- a tool
added later is left out until it is reviewed and listed, never exposed by
default -- so the model reading untrusted run content cannot fork, resume,
attest, evaluate or promote anything through this server.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

READ_ONLY_TOOLS = frozenset(
    {
        "list_runs",
        "show_run",
        "diff_runs",
        "find_actions",
        "search_runs",
        "inspect_object",
        "context_slice",
        "semantic_diff",
    }
)


class ReadOnlyTools:
    """An MCP server proxy that registers only :data:`READ_ONLY_TOOLS`."""

    def __init__(self, server: Any) -> None:
        self._server = server
        self.skipped: list[str] = []

    def tool(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        def register(function: Callable[..., Any]) -> Callable[..., Any]:
            name = kwargs.get("name") or getattr(function, "__name__", "")
            if name not in READ_ONLY_TOOLS:
                self.skipped.append(name)
                return function
            return self._server.tool(*args, **kwargs)(function)

        return register

    def resource(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        return self._server.resource(*args, **kwargs)  # resources only read

    def __getattr__(self, name: str) -> Any:
        return getattr(self._server, name)


__all__ = ["READ_ONLY_TOOLS", "ReadOnlyTools"]
