"""Bounded Ollama HTTP response readers."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from opentine.kernel import validate_json_shape

MAX_SHOW_BYTES = 8 * 1024 * 1024
MAX_CHAT_BYTES = 64 * 1024 * 1024
MAX_STREAM_BYTES = 256 * 1024 * 1024
MAX_STREAM_LINE_BYTES = 16 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


def _prepare(response: Any, max_bytes: int) -> None:
    headers = getattr(response, "headers", {})
    encoding = headers.get("content-encoding", "").strip().casefold()
    if encoding not in {"", "identity"}:
        raise ValueError("compressed Ollama responses are not accepted")
    declared = headers.get("content-length")
    if declared is None:
        return
    try:
        declared_size = int(declared)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid Ollama Content-Length") from exc
    if declared_size < 0:
        raise ValueError("invalid Ollama Content-Length")
    if declared_size > max_bytes:
        raise ValueError("Ollama response exceeds size limit")


def _loads(body: bytes | bytearray) -> dict[str, Any]:
    try:
        validate_json_shape(body, max_tokens=100_000)
        item = json.loads(body)
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise ValueError("invalid Ollama JSON response") from exc
    if not isinstance(item, dict):
        raise ValueError("Ollama response must be a JSON object")
    return item


def read_json(response: Any, *, max_bytes: int) -> dict[str, Any]:
    """Read a synchronous response without allowing unbounded buffering."""
    _prepare(response, max_bytes)
    body = bytearray()
    for chunk in response.iter_raw(chunk_size=_READ_CHUNK_BYTES):
        if len(body) + len(chunk) > max_bytes:
            raise ValueError("Ollama response exceeds size limit")
        body.extend(chunk)
    return _loads(body)


async def read_json_async(response: Any, *, max_bytes: int) -> dict[str, Any]:
    """Read an asynchronous response without allowing unbounded buffering."""
    _prepare(response, max_bytes)
    body = bytearray()
    async for chunk in response.aiter_raw(chunk_size=_READ_CHUNK_BYTES):
        if len(body) + len(chunk) > max_bytes:
            raise ValueError("Ollama response exceeds size limit")
        body.extend(chunk)
    return _loads(body)


async def iter_ndjson(response: Any) -> AsyncIterator[dict[str, Any]]:
    """Parse bounded newline-delimited Ollama stream records."""
    _prepare(response, MAX_STREAM_BYTES)
    buffered = bytearray()
    total = 0
    async for chunk in response.aiter_raw(chunk_size=_READ_CHUNK_BYTES):
        total += len(chunk)
        if total > MAX_STREAM_BYTES:
            raise ValueError("Ollama stream exceeds aggregate size limit")
        buffered.extend(chunk)
        while (newline := buffered.find(b"\n")) >= 0:
            line = bytes(buffered[:newline]).rstrip(b"\r")
            del buffered[: newline + 1]
            if len(line) > MAX_STREAM_LINE_BYTES:
                raise ValueError("Ollama stream line exceeds size limit")
            if line.strip():
                yield _loads(line)
        if len(buffered) > MAX_STREAM_LINE_BYTES:
            raise ValueError("Ollama stream line exceeds size limit")
    if buffered.strip():
        yield _loads(buffered)
