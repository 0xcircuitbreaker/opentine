"""HTTP fetch with conservative SSRF protections."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from opentine.policies import NetworkPolicy


def _is_private_host(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
    return False


def _check_url(url: str, policy: NetworkPolicy) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in policy.allowed_schemes:
        raise PermissionError(f"URL scheme denied by policy: {parsed.scheme}")
    if not parsed.hostname:
        raise PermissionError("URL host is required")
    if policy.allowed_hosts and parsed.hostname not in policy.allowed_hosts:
        raise PermissionError(f"Host denied by policy: {parsed.hostname}")
    if not policy.allow_private_hosts and _is_private_host(parsed.hostname):
        raise PermissionError(
            f"Private/link-local/loopback host denied by policy: {parsed.hostname}"
        )


async def _get(url: str, policy: NetworkPolicy) -> httpx.Response:
    proxy = os.environ.get("HTTP_PROXY")
    async with httpx.AsyncClient(
        timeout=policy.timeout_seconds,
        proxy=proxy,
        follow_redirects=False,
    ) as client:
        current = url
        for _ in range(10):
            _check_url(current, policy)
            resp = await client.get(current, headers={"User-Agent": "opentine/0.1"})
            if resp.is_redirect:
                location = resp.headers.get("location")
                if not location:
                    break
                current = urljoin(current, location)
                continue
            return resp
    raise RuntimeError("Too many redirects")


async def fetch(url: str, max_chars: int = 8000, policy: NetworkPolicy | None = None) -> str:
    """Fetch a URL and return its text content, stripped of HTML tags."""
    pol = policy or NetworkPolicy(max_body_bytes=max_chars)
    resp = await _get(url, pol)
    resp.raise_for_status()
    body = resp.content[: pol.max_body_bytes + 1]
    if len(body) > pol.max_body_bytes:
        raise ValueError(f"Response exceeds max_body_bytes={pol.max_body_bytes}")
    text = body.decode(resp.encoding or "utf-8", errors="replace")

    # Strip HTML tags for a rough text extraction
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


async def fetch_raw(url: str, policy: NetworkPolicy | None = None) -> dict[str, Any]:
    """Fetch a URL and return status, headers, and raw body."""
    pol = policy or NetworkPolicy()
    resp = await _get(url, pol)
    body = resp.content[: pol.max_body_bytes + 1]
    if len(body) > pol.max_body_bytes:
        raise ValueError(f"Response exceeds max_body_bytes={pol.max_body_bytes}")
    return {
        "status": resp.status_code,
        "headers": dict(resp.headers),
        "body": body.decode(resp.encoding or "utf-8", errors="replace"),
        "untrusted": True,
    }
