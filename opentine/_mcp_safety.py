"""MCP tools whose error text is safe to hand to a client.

FastMCP turns a tool's exception into ``str(exc)`` for the client, and loader
messages quote artifact content: a crafted ``.tine`` reached the client with raw
escape sequences (an OSC 52 clipboard write, a screen clear) in ``show_run``'s
error. Registering through :class:`SafeErrors` strips the same characters the
terminal sanitizer does from every tool and resource error. An error whose text
was already clean is re-raised untouched, type and all.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_text import BIDI_FORMATTING, INVISIBLE, plain_text

MAX_MCP_RUN_BYTES = 256 * 1024 * 1024


def confined_run(root: Path, candidate: Path) -> Path | None:
    """*candidate* resolved, if it is a ``.tine`` file inside *root* within the size cap."""
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file() or resolved.suffix != ".tine":
            return None
        if resolved.stat().st_size > MAX_MCP_RUN_BYTES:
            raise ValueError("run artifact exceeds the MCP size limit")
        return resolved
    except (OSError, ValueError):
        return None


def clip(value: Any, limit: int = 240) -> str:
    # Line breaks shown escaped; escape sequences, bidi and invisible characters
    # dropped (opentine._cli_text): run content is untrusted, the client renders it.
    text = plain_text(str(value).replace("\r", "\\r").replace("\n", "\\n"), keep="\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


#: Characters no client should receive from run content: bidi, zero-width and
#: tag characters, plus every control but newline and tab (C0, ESC, DEL, C1).
_CONTROLS = {code for code in range(0x20) if code not in (0x09, 0x0A)} | {0x7F}
_HIDDEN_ORDS = dict.fromkeys(BIDI_FORMATTING | INVISIBLE | _CONTROLS | set(range(0x80, 0xA0)))


def _clean(text: str) -> str:
    return text.translate(_HIDDEN_ORDS)


def visible(value: Any) -> Any:
    """A JSON *value* with hidden characters removed from every string and key.

    Tool results reach the client's model as text and as ``structuredContent``:
    bidi, zero-width and tag characters render as nothing, and raw control
    characters (ESC, DEL, C1) reach a client that shows structured content
    without escaping. A ``models`` entry or a resolved blob could carry either.
    The walk is iterative, so nesting depth cannot exhaust the stack.
    """
    data = json.loads(json.dumps(value, ensure_ascii=False, default=str))
    changed = False
    root = [data]
    stack: list[Any] = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            for index, item in enumerate(node):
                if isinstance(item, str):
                    cleaned = _clean(item)
                    if cleaned != item:
                        node[index], changed = cleaned, True
                elif isinstance(item, (list, dict)):
                    stack.append(item)
        else:
            for key in list(node):
                item = node[key]
                cleaned_key = _clean(key)
                if cleaned_key != key:
                    del node[key]
                    node[cleaned_key], changed = item, True
                    key = cleaned_key
                if isinstance(item, str):
                    cleaned = _clean(item)
                    if cleaned != item:
                        node[key], changed = cleaned, True
                elif isinstance(item, (list, dict)):
                    stack.append(item)
    return root[0] if changed else value


def hidden_name(name: str) -> bool:
    """Whether a file *name* carries characters a client could not see or render.

    A listing cannot clean such a name -- the client would be told a path that
    resolves to nothing -- so it leaves the file out instead.
    """
    return plain_text(name) != name


def server_class() -> Any:
    """SDK 2.x's ``MCPServer``, or 1.x's ``FastMCP``: the same decorator API."""
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError:
        try:
            from mcp.server.fastmcp import FastMCP
        except ImportError as exc:  # pragma: no cover - optional integration
            raise RuntimeError("Install the mcp package to run opentine's MCP server.") from exc
        return FastMCP
    return MCPServer


def total_bytes(paths: list[Path]) -> int:
    """The bytes *paths* hold: what MCP forks have already written, summed.

    The per-run fork bound alone let a model write 5,000 runs of 32 MiB each.
    """
    total = 0
    for path in paths:
        try:
            total += path.lstat().st_size
        except OSError:
            continue  # removed meanwhile
    return total


def _plain_errors(
    function: Callable[..., Any], tool_error: type | None = None
) -> Callable[..., Any]:
    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            # Every result, not only the fields a tool remembered to clean: run
            # files, file names and resolved blobs are untrusted (final pass 5, #7).
            return visible(function(*args, **kwargs))
        except Exception as exc:
            text = str(exc)
            clean = plain_text(text, keep="\n\t")
            if tool_error is not None:
                # SDK 2.x tells a client only "Error executing tool" for anything but
                # its own ToolError; the cleaned message is what the client needs.
                raise tool_error(clean or type(exc).__name__) from None
            if clean == text:
                raise
            raise ValueError(clean or type(exc).__name__) from None

    return wrapper


def _sdk_tool_error(server: Any) -> type | None:
    """SDK 2.x's ``ToolError`` when *server* is an ``MCPServer``; ``None`` for 1.x."""
    if not type(server).__module__.startswith("mcp.server.mcpserver"):
        return None
    from mcp.server.mcpserver.exceptions import ToolError

    return ToolError


class SafeErrors:
    """An MCP server proxy whose ``tool``/``resource`` registrations sanitize results and errors."""

    def __init__(self, server: Any) -> None:
        self._server = server
        self._tool_error = _sdk_tool_error(server)

    def tool(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        register = self._server.tool(*args, **kwargs)
        return lambda function: register(_plain_errors(function, self._tool_error))

    def resource(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        register = self._server.resource(*args, **kwargs)
        return lambda function: register(_plain_errors(function, self._tool_error))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._server, name)


def safe_errors(server: Any) -> SafeErrors:
    return server if isinstance(server, SafeErrors) else SafeErrors(server)


__all__ = [
    "MAX_MCP_RUN_BYTES",
    "SafeErrors",
    "clip",
    "confined_run",
    "hidden_name",
    "safe_errors",
    "server_class",
    "total_bytes",
    "visible",
]
