"""``python -m opentine.mcp_server``: read-only by default; this module enforces it.

The Claude Code plugin (``tine plugin export``) points its ``.mcp.json`` here.
Registration goes through an **allowlist** derived from the one tool registry
(:mod:`opentine._mcp_registry`): a tool without an entry is left out until it is
reviewed and listed, never exposed by default, and a tool annotated
``writes=True`` only with writes opted into -- so the model reading untrusted
run content cannot fork, resume, attest, evaluate or promote anything through
the default server.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from opentine._mcp_registry import exposed

READ_ONLY_TOOLS = exposed(allow_writes=False)
WRITE_MODE_TOOLS = exposed(allow_writes=True)


class ReadOnlyTools:
    """An MCP server proxy that registers only the registry's tools for this mode.

    Read tools only (:data:`READ_ONLY_TOOLS`) unless ``allow_writes``; then the
    annotated write set as well (:data:`WRITE_MODE_TOOLS`), and nothing else.
    """

    def __init__(self, server: Any, *, allow_writes: bool = False) -> None:
        self._server = server
        self._allowed = WRITE_MODE_TOOLS if allow_writes else READ_ONLY_TOOLS
        self.skipped: list[str] = []

    def tool(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        def register(function: Callable[..., Any]) -> Callable[..., Any]:
            name = kwargs.get("name") or getattr(function, "__name__", "")
            if name not in self._allowed:
                self.skipped.append(name)
                return function
            return self._server.tool(*args, **kwargs)(function)

        return register

    def resource(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        return self._server.resource(*args, **kwargs)  # resources only read

    def __getattr__(self, name: str) -> Any:
        return getattr(self._server, name)


#: Set to ``1`` to expose the write tools (fork, resume, attest, evaluate, ...).
ALLOW_WRITES_ENV = "OPENTINE_MCP_ALLOW_WRITES"


def writes_allowed(argv: list[str] | None = None) -> bool:
    """Write tools are opt-in: ``--allow-writes`` or ``OPENTINE_MCP_ALLOW_WRITES=1``.

    ``--read-only`` always wins, so an existing read-only configuration stays one.
    """
    if argv is not None and "--read-only" in argv:
        return False
    if argv is not None and "--allow-writes" in argv:
        return True
    return os.environ.get(ALLOW_WRITES_ENV, "").strip() == "1"


__all__ = [
    "ALLOW_WRITES_ENV",
    "READ_ONLY_TOOLS",
    "WRITE_MODE_TOOLS",
    "ReadOnlyTools",
    "writes_allowed",
]
