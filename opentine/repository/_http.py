"""Bounded HTTP response handling shared by repository clients."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse, urlsplit

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


def raise_for_status(response: httpx.Response) -> None:
    """Refuse a non-2xx response without echoing the URL's credentials or query.

    httpx's own message carries the full request URL, so a token in a query
    string or in userinfo travelled into tracebacks, CLI errors and CI logs.
    """
    if response.is_success:
        return
    path = urlparse(str(response.request.url)).path
    raise ValueError(f"remote returned HTTP {response.status_code} for {path}")


def require_secure_remote(base: str, allow_insecure: bool) -> None:
    parsed = urlparse(base)
    # A request path is joined onto the base, so a query string there ended up in
    # the middle of every URL -- and credentials in it or in userinfo were echoed.
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError(
            "remote URL must not carry credentials, a query or a fragment; "
            "pass the token with --token-file or TINE_REMOTE_TOKEN"
        )
    # Only the two schemes the transport speaks: the loopback exemption below used
    # to wave through ``ftp://127.0.0.1`` (refused later, by httpx, by accident).
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("remote URL must be https:// (or http:// to a loopback address)")
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
                raise_for_status(response)
            return response.status_code, read_json(response, max_seconds=max_seconds)

    return run_request(session, max_seconds, "control request", operation)


def request_pack(
    session: httpx.Client,
    method: str,
    url: str,
    *,
    max_seconds: float = 120,
    response_headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> bytes:
    def operation() -> bytes:
        with session.stream(method, url, **kwargs) as response:
            raise_for_status(response)
            if response_headers is not None:
                response_headers.update((k.lower(), v) for k, v in response.headers.items())
            return read_pack(response, max_seconds=max_seconds)

    return run_request(session, max_seconds, "pack request", operation)


#: The tenant-name grammar the server enforces (``remote.valid_tenant``).
_TENANT = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")


def split_remote(remote: str, tenant: str | None) -> tuple[str, str]:
    url = remote.rstrip("/")
    # Checked on the URL as given: splitting off an embedded tenant first left a
    # ``?token=...`` inside the tenant, sent in every request path and echoed in
    # errors.
    parsed = urlsplit(url)
    if parsed.query or parsed.fragment or parsed.username or parsed.password or "?" in url:
        raise ValueError(
            "remote URL must not carry credentials, a query or a fragment; "
            "pass the token with --token-file or TINE_REMOTE_TOKEN"
        )
    marker = "/v1/tenants/"
    if marker in url:
        base, embedded = url.split(marker, 1)
        name = tenant or embedded.split("/", 1)[0]
    elif tenant:
        base, name = url, tenant
    else:
        raise ValueError("tenant is required unless embedded in the remote URL")
    if not _TENANT.fullmatch(name):
        raise ValueError("tenant must match [a-z0-9][a-z0-9._-]*")
    return base, name
