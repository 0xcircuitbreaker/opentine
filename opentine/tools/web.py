"""HTTP fetch with conservative SSRF protections."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from opentine.policies import NetworkPolicy
from opentine.tools._html import visible_text

_RESOLVER_SLOTS = threading.BoundedSemaphore(8)


async def _resolve(host: str, port: int):
    """Resolve without making event-loop shutdown wait for a stuck system resolver."""
    if not _RESOLVER_SLOTS.acquire(blocking=False):
        raise RuntimeError("network resolver capacity is exhausted")
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def resolve() -> None:
        try:
            result = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            error = None
        except BaseException as exc:
            result, error = None, exc
        finally:
            _RESOLVER_SLOTS.release()

        def deliver() -> None:
            if future.done():
                return
            if error is not None:
                future.set_exception(error)
            else:
                future.set_result(result)

        try:
            loop.call_soon_threadsafe(deliver)
        except RuntimeError:
            pass

    worker = threading.Thread(target=resolve, daemon=True)
    try:
        worker.start()
    except BaseException:
        _RESOLVER_SLOTS.release()
        raise
    return await future


def _check_url(url: str, policy: NetworkPolicy):
    parsed = urlparse(url)
    if parsed.scheme not in policy.allowed_schemes:
        raise PermissionError(f"URL scheme denied by policy: {parsed.scheme}")
    if not parsed.hostname:
        raise PermissionError("URL host is required")
    if policy.allowed_hosts and parsed.hostname not in policy.allowed_hosts:
        raise PermissionError(f"Host denied by policy: {parsed.hostname}")
    if parsed.username is not None or parsed.password is not None:
        raise PermissionError("URL credentials are not accepted")
    try:
        parsed.port
    except ValueError as exc:
        raise PermissionError("URL port is invalid") from exc
    try:
        literal = ipaddress.ip_address(parsed.hostname.split("%", 1)[0])
    except ValueError:
        pass
    else:
        if not policy.allow_private_hosts and not literal.is_global:
            raise PermissionError(
                f"Private/link-local/loopback host denied by policy: {parsed.hostname}"
            )
    return parsed


async def _pin_url(url: str, policy: NetworkPolicy) -> tuple[str, str, str]:
    parsed = _check_url(url, policy)
    hostname = parsed.hostname.encode("idna").decode("ascii")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = await _resolve(hostname, port)
    except socket.gaierror as exc:
        raise PermissionError(f"URL host could not be resolved: {hostname}") from exc
    addresses = []
    for info in infos:
        raw = info[4][0].split("%", 1)[0]
        address = ipaddress.ip_address(raw)
        if not policy.allow_private_hosts and not address.is_global:
            raise PermissionError(
                f"Private/link-local/loopback host denied by policy: {parsed.hostname}"
            )
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise PermissionError(f"URL host could not be resolved: {hostname}")
    address = addresses[0]
    literal = f"[{address.compressed}]" if address.version == 6 else address.compressed
    explicit_port = parsed.port
    authority = literal + (f":{explicit_port}" if explicit_port is not None else "")
    default_port = 443 if parsed.scheme == "https" else 80
    try:
        origin = ipaddress.ip_address(hostname)
        origin_host = f"[{hostname}]" if origin.version == 6 else hostname
    except ValueError:
        origin_host = hostname
    host_header = origin_host + (f":{port}" if port != default_port else "")
    return parsed._replace(netloc=authority, fragment="").geturl(), host_header, hostname


async def _get_within_deadline(url: str, policy: NetworkPolicy) -> httpx.Response:
    async with httpx.AsyncClient(
        timeout=policy.timeout_seconds,
        trust_env=False,
        follow_redirects=False,
        limits=httpx.Limits(max_keepalive_connections=0),
    ) as client:
        current = url
        for _ in range(10):
            pinned, host, sni = await _pin_url(current, policy)
            async with client.stream(
                "GET",
                pinned,
                headers={
                    "Accept-Encoding": "identity",
                    "Host": host,
                    "User-Agent": "opentine/0.3",
                },
                extensions={"sni_hostname": sni},
            ) as resp:
                if resp.is_redirect:
                    location = resp.headers.get("location")
                    if not location:
                        break
                    current = urljoin(current, location)
                    continue
                encoding = resp.headers.get("content-encoding", "identity").casefold()
                if encoding not in {"", "identity"}:
                    raise ValueError("compressed web responses are not accepted")
                declared = resp.headers.get("content-length")
                if declared is not None:
                    try:
                        length = int(declared)
                    except ValueError as exc:
                        raise ValueError("web response has invalid Content-Length") from exc
                    if length < 0 or length > policy.max_body_bytes:
                        raise ValueError(f"Response exceeds max_body_bytes={policy.max_body_bytes}")
                body = bytearray()
                async for chunk in resp.aiter_raw():
                    body.extend(chunk)
                    if len(body) > policy.max_body_bytes:
                        raise ValueError(f"Response exceeds max_body_bytes={policy.max_body_bytes}")
                return httpx.Response(
                    resp.status_code,
                    content=bytes(body),
                    headers=resp.headers,
                    request=resp.request,
                )
    raise RuntimeError("Too many redirects")


async def _get(url: str, policy: NetworkPolicy) -> httpx.Response:
    if policy.max_body_bytes < 1 or policy.timeout_seconds <= 0:
        raise ValueError("network body and timeout limits must be positive")
    async with asyncio.timeout(policy.timeout_seconds):
        return await _get_within_deadline(url, policy)


async def fetch(url: str, max_chars: int = 8000, policy: NetworkPolicy | None = None) -> str:
    """Fetch a URL and return its text content, stripped of HTML tags."""
    pol = policy or NetworkPolicy(max_body_bytes=max_chars)
    resp = await _get(url, pol)
    resp.raise_for_status()
    body = resp.content
    text = body.decode(resp.encoding or "utf-8", errors="replace")

    return visible_text(text, max_chars)


async def fetch_raw(url: str, policy: NetworkPolicy | None = None) -> dict[str, Any]:
    """Fetch a URL and return status, headers, and raw body."""
    pol = policy or NetworkPolicy()
    resp = await _get(url, pol)
    body = resp.content
    return {
        "status": resp.status_code,
        "headers": dict(resp.headers),
        "body": body.decode(resp.encoding or "utf-8", errors="replace"),
        "untrusted": True,
    }


# Models choose the URL; the embedding host owns body/output ceilings and policy.
fetch.__opentine_hidden_parameters__ = frozenset({"max_chars", "policy"})
fetch_raw.__opentine_hidden_parameters__ = frozenset({"policy"})
