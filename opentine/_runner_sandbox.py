"""The review runner's sandbox: egress only to the user's model endpoints (0.55).

A runner's sandbox policy is derived from its config alone::

    {"label": "review runner", "network": "allowlist",
     "egress": ["api.example.com:443", ...],      # the configured model endpoints
     "credentials": ["MODEL_API_KEY", ...],       # env names passed through, never values
     "filesystem": "worktree-read-only, workdir-write"}

Its digest (``sha256:`` over JCS) is recorded in every step's evidence, so a
reader can tell which policy a finding or verdict was produced under.

:class:`EgressGuard` enforces the policy inside the runner's own process with a
:func:`sys.addaudithook` hook: while a guard is active, a name lookup of any
host outside the allowlist and a connect to any ``(address, port)`` the
allowlisted endpoints did not resolve to raise :class:`EgressRefused`. Local
Unix sockets stay usable. Reviewer subprocesses are held to the same allowlist
by the container's network policy (``deploy/review-runner``); the guard covers
the runner itself. Nothing here is a wire format: the policy is a local
document and only its digest leaves the runner.
"""

from __future__ import annotations

import hashlib
import socket
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

from opentine.kernel import canonical_json

LABEL = "review runner"
FILESYSTEM = "worktree-read-only, workdir-write"


class EgressRefused(PermissionError):
    """A network call to a host the sandbox policy does not allow."""


def endpoint(url: str) -> tuple[str, int]:
    """``(host, port)`` of an ``https://`` (or loopback ``http://``) model endpoint."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("https", "http") or not host or parts.username or parts.password:
        raise ValueError(f"a model endpoint is an https URL without credentials: {url!r}")
    if parts.scheme == "http" and host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"a remote model endpoint must use https: {url!r}")
    return host, parts.port or (443 if parts.scheme == "https" else 80)


def policy(endpoints: list[str], credentials: list[str]) -> dict[str, Any]:
    hosts = sorted({f"{host}:{port}" for host, port in map(endpoint, endpoints)})
    return {"label": LABEL, "network": "allowlist", "egress": hosts,
            "credentials": sorted(set(credentials)), "filesystem": FILESYSTEM}  # fmt: skip


def digest(document: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()


_LOCK = threading.Lock()
# sendto/sendmsg too: a UDP datagram (say, a hand-rolled DNS query) needs no connect
_EVENTS = ("socket.getaddrinfo", "socket.connect", "socket.sendto", "socket.sendmsg")
_ACTIVE: list[EgressGuard] = []
_HOOKED = False


def _hook(event: str, args: tuple[Any, ...]) -> None:
    if not _ACTIVE or event not in _EVENTS:
        return
    guard = _ACTIVE[-1]
    if event == "socket.getaddrinfo":
        host = args[0].decode("ascii", "replace") if isinstance(args[0], bytes) else args[0]
        if host is not None and str(host).lower() not in guard.hosts:
            raise EgressRefused(f"egress to {host} is outside the runner's sandbox policy")
        return
    address = args[-1] if event == "socket.sendmsg" else args[1]
    if isinstance(address, tuple) and len(address) >= 2:
        where = (str(address[0]), int(address[1]))
        if where not in guard.addresses and where not in guard.resolve():
            raise EgressRefused(f"egress to {address[0]}:{address[1]} is outside the policy")


class EgressGuard:
    """Refuse every lookup and connect outside *document*'s egress allowlist."""

    def __init__(self, document: dict[str, Any]) -> None:
        self.endpoints = [
            (h, int(p)) for h, _, p in (e.rpartition(":") for e in document["egress"])
        ]
        self.hosts: set[str] = {host for host, _ in self.endpoints}
        self.addresses: set[tuple[str, int]] = set()
        self.resolve()

    def resolve(self) -> set[tuple[str, int]]:
        """The addresses the allowed endpoints resolve to now (an unresolvable one: none)."""
        for host, port in self.endpoints:
            try:
                infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
            except OSError:
                continue
            for info in infos:
                self.addresses.add((str(info[4][0]), port))
                self.hosts.add(str(info[4][0]))
        return self.addresses

    def __enter__(self) -> EgressGuard:
        global _HOOKED
        with _LOCK:
            if not _HOOKED:
                sys.addaudithook(_hook)  # an audit hook cannot be removed: it idles when unused
                _HOOKED = True
            _ACTIVE.append(self)
        return self

    def __exit__(self, *_exc: object) -> None:
        with _LOCK:
            _ACTIVE.remove(self)


__all__ = ["LABEL", "EgressGuard", "EgressRefused", "digest", "endpoint", "policy"]
