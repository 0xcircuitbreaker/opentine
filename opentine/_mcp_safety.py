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
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_text import plain_text

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


def _plain_errors(function: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except Exception as exc:
            text = str(exc)
            clean = plain_text(text, keep="\n\t")
            if clean == text:
                raise
            raise ValueError(clean or type(exc).__name__) from None

    return wrapper


class SafeErrors:
    """An MCP server proxy whose ``tool``/``resource`` registrations sanitize errors."""

    def __init__(self, server: Any) -> None:
        self._server = server

    def tool(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        register = self._server.tool(*args, **kwargs)
        return lambda function: register(_plain_errors(function))

    def resource(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        register = self._server.resource(*args, **kwargs)
        return lambda function: register(_plain_errors(function))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._server, name)


def safe_errors(server: Any) -> SafeErrors:
    return server if isinstance(server, SafeErrors) else SafeErrors(server)


__all__ = ["MAX_MCP_RUN_BYTES", "SafeErrors", "clip", "confined_run", "safe_errors"]
