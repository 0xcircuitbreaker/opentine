"""Deterministic cleanup for short-lived provider SDK clients."""

from __future__ import annotations

import inspect
import warnings
from contextlib import asynccontextmanager
from typing import Any


@asynccontextmanager
async def closing_client(client: Any):
    """Close sync or async SDK clients after the full response/stream is consumed."""
    try:
        yield client
    finally:
        await _safe_close(client)
        asynchronous = getattr(client, "aio", None)
        if asynchronous is not None and asynchronous is not client:
            await _safe_close(asynchronous)


async def _safe_close(client: Any) -> None:
    try:
        await _close(client)
    except Exception:
        warnings.warn("provider SDK client cleanup failed", ResourceWarning, stacklevel=2)


async def _close(client: Any) -> None:
    closer = getattr(client, "close", None) or getattr(client, "aclose", None)
    if closer is not None:
        result = closer()
        if inspect.isawaitable(result):
            await result
