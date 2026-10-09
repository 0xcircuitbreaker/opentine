"""Refuse to send an API key over cleartext HTTP to another machine.

Every OpenAI-compatible adapter accepted ``http://`` for any host, so the key
for a LAN server or a ``*_BASE_URL`` override crossed the network in the clear,
readable by anything on the path. A key now travels over plain HTTP only to a
loopback address, or with an explicit opt-in. A local server's placeholder key
(``lm-studio``, ``vllm``) is no secret and is sent anywhere.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlsplit

#: ``1`` opts every adapter in to keys over cleartext HTTP (a trusted network).
INSECURE_ENV = "OPENTINE_ALLOW_INSECURE_ENDPOINTS"


def _loopback(host: str | None) -> bool:
    if not host:
        return False
    if host.lower().rstrip(".") == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return address.is_loopback or bool(mapped and mapped.is_loopback)


def require_key_transport(
    url: str | None,
    api_key: str | None,
    *,
    placeholder: bool = False,
    allow_insecure: bool = False,
) -> None:
    """Raise unless *api_key* reaches *url* encrypted, locally, or by opt-in."""
    if not url or not api_key or placeholder or allow_insecure:
        return
    parts = urlsplit(url.strip())
    if parts.scheme.lower() != "http" or _loopback(parts.hostname):
        return
    if os.environ.get(INSECURE_ENV) == "1":
        return
    raise ValueError(
        f"refusing to send an API key over cleartext http:// to {parts.hostname!r}: use "
        f"https://, a loopback address, or opt in with allow_insecure=True or {INSECURE_ENV}=1"
    )
