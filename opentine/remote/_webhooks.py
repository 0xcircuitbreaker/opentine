"""Per-tenant webhook registrations and the server's Ed25519 webhook key (0.45.1).

Registrations live in ``<state>/webhooks/<tenant>.json`` (at most
:data:`MAX_HOOKS` per tenant, admin only). A target URL must be ``https://``
and resolve only to global addresses: loopback, private, link-local, CGNAT,
multicast and reserved ranges are refused at registration (for an IP literal)
and again at every delivery, against each address the name resolves to, and the
delivery connects to the address that was checked (no DNS-rebinding window).
``tine serve --webhooks-allow-private`` lifts both rules for a self-hosted
receiver on a private network, ``http://`` included.

The signing key is ``<state>/webhook-ed25519.key`` (raw 32-byte seed, mode
0600), created on first start; its public half is advertised under
``caps.webhooks.keys``.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _webhook_sig
from opentine.remote._events import KINDS
from opentine.remote.backend import valid_tenant

MAX_HOOKS = 16
MAX_URL = 2048
KEY_FILE = "webhook-ed25519.key"


def load_key(state: Path) -> Ed25519PrivateKey:
    path = state / KEY_FILE
    try:
        seed = path.read_bytes()
    except FileNotFoundError:
        seed = secrets.token_bytes(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(seed)
    if len(seed) != 32:
        raise ValueError(f"{KEY_FILE} must hold a 32-byte Ed25519 seed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(text.split("%", 1)[0])
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped or ip


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.sixtofour or (ip.teredo or (None, None))[1]
        if embedded is None and ip in _NAT64:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None and blocked(embedded):
            return True
    return not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified


def check_url(url: Any, allow_private: bool) -> tuple[str, str, int]:
    """``(scheme, host, port)`` of an acceptable target; ``ValueError`` otherwise."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL:
        raise ValueError("webhook url must be a string of at most 2048 characters")
    parts = urlsplit(url)
    allowed = {"https", "http"} if allow_private else {"https"}
    if parts.scheme not in allowed or not parts.hostname:
        raise ValueError("webhook url must be https:// (http:// only with allow-private)")
    if parts.username or parts.password or parts.fragment:
        raise ValueError("webhook url must not carry credentials or a fragment")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        literal = _address(parts.hostname)
    except ValueError:
        literal = None
    if literal is not None and blocked(literal) and not allow_private:
        raise ValueError("webhook url targets a private, loopback or reserved address")
    if parts.hostname.rstrip(".").lower() == "localhost" and not allow_private:
        raise ValueError("webhook url targets a private, loopback or reserved address")
    return parts.scheme, parts.hostname, port


def resolve(host: str, port: int, allow_private: bool, resolver=socket.getaddrinfo) -> str:
    """The one address a delivery connects to, after checking every address of *host*."""
    infos = resolver(host, port, type=socket.SOCK_STREAM)
    addresses = [_address(str(info[4][0])) for info in infos]
    if not addresses:
        raise ValueError("webhook host did not resolve")
    if not allow_private and any(blocked(ip) for ip in addresses):
        raise ValueError("webhook host resolves to a private, loopback or reserved address")
    return str(addresses[0])


class Webhooks:
    def __init__(self, state: str | Path, *, allow_private: bool = False):
        self.state = Path(state)
        self.root = self.state / "webhooks"
        self.root.mkdir(parents=True, exist_ok=True)
        self.allow_private = allow_private
        self.key = load_key(self.state)
        self._lock = threading.Lock()
        self.dispatcher: Any = None  # set by ``_webhook_delivery.attach``

    def capabilities(self) -> dict[str, Any]:
        raw = self.key.public_key().public_bytes_raw()
        entry = {"alg": "ed25519", "kid": _webhook_sig.key_id(raw)}
        entry["public_key"] = _webhook_sig.b64url(raw)
        return {
            "format": _webhook_sig.FORMAT,
            "header": _webhook_sig.HEADER,
            "keys": [entry],
            "kinds": list(KINDS),
            "replay_window": _webhook_sig.REPLAY_WINDOW,
        }

    def _path(self, tenant: str) -> Path:
        return self.root / f"{valid_tenant(tenant)}.json"

    def list(self, tenant: str) -> list[dict[str, Any]]:
        try:
            hooks = json.loads(self._path(tenant).read_text("utf-8"))
        except FileNotFoundError:
            return []
        return hooks if isinstance(hooks, list) else []

    def _write(self, tenant: str, hooks: list[dict[str, Any]]) -> None:
        path = self._path(tenant)
        temp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
        temp.write_text(json.dumps(hooks, sort_keys=True), encoding="utf-8")
        os.replace(temp, path)

    def add(self, tenant: str, url: Any, kinds: Any = None) -> dict[str, Any]:
        check_url(url, self.allow_private)
        chosen = list(KINDS) if kinds is None else kinds
        if not isinstance(chosen, list) or not chosen or set(chosen) - set(KINDS):
            raise ValueError(f"webhook kinds must be a non-empty subset of {list(KINDS)}")
        hook = {"created": datetime.now(UTC).isoformat().replace("+00:00", "Z")}
        hook.update({"id": "wh_" + secrets.token_hex(8), "kinds": sorted(set(chosen)), "url": url})
        with self._lock:
            hooks = self.list(tenant)
            if len(hooks) >= MAX_HOOKS:
                raise ValueError(f"a tenant has at most {MAX_HOOKS} webhooks")
            self._write(tenant, [*hooks, hook])
        return hook

    def remove(self, tenant: str, hook_id: str) -> None:
        with self._lock:
            hooks = self.list(tenant)
            kept = [hook for hook in hooks if hook.get("id") != hook_id]
            if len(kept) == len(hooks):
                raise KeyError(hook_id)
            self._write(tenant, kept)


__all__ = ["MAX_HOOKS", "Webhooks", "blocked", "check_url", "load_key", "resolve"]
