"""Bounded HTTP response handling shared by repository clients."""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx

from opentine.kernel import validate_json_shape
from opentine.repository.pack import MAX_PACK_BYTES

MAX_CONTROL_BYTES = 1024 * 1024
_REQUEST_SLOTS = threading.BoundedSemaphore(8)


def run_request(
    session: httpx.Client, seconds: float, label: str, operation: Callable[[], Any]
) -> Any:
    """Run a synchronous request behind a capped, daemonized wall deadline."""
    if seconds <= 0:
        raise ValueError("request deadline must be positive")
    if not _REQUEST_SLOTS.acquire(blocking=False):
        raise RuntimeError("remote request worker capacity is exhausted")
    done = threading.Event()
    outcome: list[tuple[bool, Any]] = []

    def invoke() -> None:
        try:
            outcome.append((True, operation()))
        except BaseException as exc:
            outcome.append((False, exc))
        finally:
            _REQUEST_SLOTS.release()
            done.set()

    worker = threading.Thread(target=invoke, daemon=True)
    try:
        worker.start()
    except BaseException:
        _REQUEST_SLOTS.release()
        raise
    try:
        completed = done.wait(seconds)
    except BaseException:
        session.close()
        raise
    if not completed:
        session.close()
        raise ValueError(f"remote {label} exceeded total request deadline")
    succeeded, result = outcome[0]
    if succeeded:
        return result
    raise result


def require_secure_remote(base: str, allow_insecure: bool) -> None:
    parsed = urlparse(base)
    try:
        literal_loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        literal_loopback = False
    if parsed.scheme != "https" and not (allow_insecure or literal_loopback):
        raise ValueError("remote requires HTTPS; opt into insecure development explicitly")


def client(
    base: str,
    token: str | None,
    *,
    allow_insecure: bool,
    timeout: float,
) -> httpx.Client:
    require_secure_remote(base, allow_insecure)
    secret = token or os.environ.get("TINE_REMOTE_TOKEN")
    if not secret:
        raise ValueError("remote bearer token is required")
    return httpx.Client(
        base_url=base,
        headers={"Authorization": f"Bearer {secret}"},
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    )


def _read_limited(response: httpx.Response, limit: int, label: str, max_seconds: float) -> bytes:
    if max_seconds <= 0:
        raise ValueError("response deadline must be positive")
    started = time.monotonic()
    declared = response.headers.get("content-length")
    if declared is not None:
        try:
            length = int(declared)
        except ValueError as exc:
            raise ValueError(f"remote {label} has invalid Content-Length") from exc
        if length < 0 or length > limit:
            raise ValueError(f"remote {label} exceeds maximum transfer size")
    data = bytearray()
    # Eager in-memory transports may arrive consumed; network responses passed
    # by request_json/read_pack remain streaming and take the raw-byte path.
    chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
    for chunk in chunks:
        if time.monotonic() - started > max_seconds:
            raise ValueError(f"remote {label} exceeded total response deadline")
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError(f"remote {label} exceeds maximum transfer size")
    return bytes(data)


def read_pack(
    response: httpx.Response, limit: int = MAX_PACK_BYTES, max_seconds: float = 120
) -> bytes:
    return _read_limited(response, limit, "pack", max_seconds)


def read_json(
    response: httpx.Response, limit: int = MAX_CONTROL_BYTES, max_seconds: float = 30
) -> dict[str, Any]:
    encoding = response.headers.get("content-encoding", "").strip().lower()
    if encoding not in {"", "identity"}:
        raise ValueError("remote control response uses unsupported Content-Encoding")
    raw = _read_limited(response, limit, "control response", max_seconds)
    try:
        validate_json_shape(raw, max_tokens=100_000)
        value = json.loads(raw)
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise ValueError("remote returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("remote control response must be a JSON object")
    return value


def request_json(
    session: httpx.Client,
    method: str,
    url: str,
    *,
    allowed: tuple[int, ...] = (200,),
    max_seconds: float = 30,
    **kwargs: Any,
) -> tuple[int, dict[str, Any]]:
    def operation() -> tuple[int, dict[str, Any]]:
        with session.stream(method, url, **kwargs) as response:
            if response.status_code not in allowed:
                response.raise_for_status()
            return response.status_code, read_json(response, max_seconds=max_seconds)

    return run_request(session, max_seconds, "control request", operation)


def request_pack(
    session: httpx.Client,
    method: str,
    url: str,
    *,
    max_seconds: float = 120,
    **kwargs: Any,
) -> bytes:
    def operation() -> bytes:
        with session.stream(method, url, **kwargs) as response:
            response.raise_for_status()
            return read_pack(response, max_seconds=max_seconds)

    return run_request(session, max_seconds, "pack request", operation)
