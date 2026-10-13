"""JWKS key sets: validation, and the refresh that makes issuer key rotation work.

A discovered JWKS used to be fetched once, at startup, and never again: a key the
issuer rotated in was refused until a restart, and a key it rotated *out* -- say
because it leaked -- kept verifying tokens for as long as the server ran. A key
set built with a ``fetch`` is now refetched when a token names an unknown ``kid``
and once it is older than ``max_age``, at most once per ``refresh_interval`` so a
stream of made-up ``kid`` values cannot turn the server into a request amplifier
against the issuer. A failed refetch keeps the current keys until ``max_age``;
after that every token is refused rather than verified against keys the issuer
may have revoked. A static JWKS (no ``fetch``) is the operator's own pin and never
expires.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from typing import Any

MAX_JWKS_KEYS = 100
DEFAULT_REFRESH_INTERVAL = 60.0
DEFAULT_MAX_KEY_AGE = 3600.0


class OIDCError(PermissionError):
    pass


def parse_keys(jwks: Any) -> dict[str, dict[str, Any]]:
    keys = jwks.get("keys", []) if isinstance(jwks, dict) else jwks
    if not isinstance(keys, list) or not keys or len(keys) > MAX_JWKS_KEYS:
        raise OIDCError(f"JWKS must contain between 1 and {MAX_JWKS_KEYS} keys")
    parsed: dict[str, dict[str, Any]] = {}
    for key in keys:
        kid = key.get("kid") if isinstance(key, dict) else None
        if not isinstance(kid, str) or not kid or kid in parsed:
            raise OIDCError("JWKS key ids must be unique non-empty strings")
        parsed[kid] = key
    return parsed


def _seconds(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and value > 0
    )


class KeySet:
    """The verification keys for one issuer, refreshed from ``fetch`` when given."""

    def __init__(
        self,
        jwks: Any,
        *,
        fetch: Callable[[], Any] | None = None,
        refresh_interval: float = DEFAULT_REFRESH_INTERVAL,
        max_age: float = DEFAULT_MAX_KEY_AGE,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not _seconds(refresh_interval) or not _seconds(max_age) or refresh_interval > max_age:
            raise OIDCError("JWKS refresh interval must be positive and within the maximum age")
        self._keys = parse_keys(jwks)
        self._fetch = fetch
        self.refresh_interval = refresh_interval
        self.max_age = max_age
        self._clock = clock
        self._loaded = self._attempted = clock()
        # Held across the refetch on purpose: concurrent requests wait for one
        # fetch instead of each starting their own (the refetch is rate-limited
        # and the fetch callable carries its own timeout).
        self._lock = threading.Lock()

    @property
    def keys(self) -> dict[str, dict[str, Any]]:
        return self._keys

    def get(self, kid: str) -> dict[str, Any] | None:
        if self._fetch is None:
            return self._keys.get(kid)
        with self._lock:
            now = self._clock()
            stale = now - self._loaded >= self.max_age
            due = now - self._attempted >= self.refresh_interval
            if (stale or kid not in self._keys) and due:
                self._refresh(now)
            if now - self._loaded >= self.max_age:
                raise OIDCError("JWKS is past its maximum age and could not be refreshed")
            return self._keys.get(kid)

    def _refresh(self, now: float) -> None:
        self._attempted = now
        try:
            keys = parse_keys(self._fetch())
        except Exception:
            # Any failure -- network, HTTP status, a malformed document -- keeps
            # the current keys; get() refuses them once they pass max_age.
            return
        self._keys = keys
        self._loaded = now
