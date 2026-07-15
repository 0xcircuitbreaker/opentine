"""Bounded HTTP response handling shared by repository clients."""

from __future__ import annotations

import json
import os
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from opentine.repository.pack import MAX_PACK_BYTES

MAX_CONTROL_BYTES = 1024 * 1024


def require_secure_remote(base: str, allow_insecure: bool) -> None:
    parsed = urlparse(base)
    if parsed.scheme != "https" and not (
        allow_insecure or parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
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
    for chunk in response.iter_bytes():
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
    raw = _read_limited(response, limit, "control response", max_seconds)
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
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
    with session.stream(method, url, **kwargs) as response:
        if response.status_code not in allowed:
            response.raise_for_status()
        return response.status_code, read_json(response, max_seconds=max_seconds)
