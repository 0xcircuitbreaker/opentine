"""SPEC 8.13: verify a signed ``tine-webhook/1`` delivery, stdlib only (0.45.1).

The pyz's port of :func:`opentine._webhook_sig.verify`: the same header
grammar, replay window, pinned key id and order of answers, with Ed25519 from
the pure-Python :mod:`._ed25519`. Returns the class (``valid``, ``malformed``,
``stale``, ``unknown-key``, ``bad-signature``) instead of raising.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from . import _ed25519

MAX_BODY = 256 * 1024
_HEADER = re.compile(r"^t=([0-9]{1,12}),kid=(ed25519:[0-9a-f]{16}),sig=([A-Za-z0-9_-]{86})$")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def classify(body: bytes, header: str, keys: dict[str, bytes], now: float, window: int) -> str:
    match = _HEADER.fullmatch(header.strip())
    if match is None or len(body) > MAX_BODY:
        return "malformed"
    stamp, kid, sig = int(match.group(1)), match.group(2), match.group(3)
    if abs(now - stamp) > window:
        return "stale"
    if kid not in keys:
        return "unknown-key"
    signed = b"opentine-webhook/1\n" + str(stamp).encode("ascii") + b"\n" + body
    try:
        good = len(keys[kid]) == 32 and _ed25519.verify(keys[kid], signed, _unb64url(sig))
    except (ValueError, binascii.Error):
        good = False
    if not good:
        return "bad-signature"
    try:
        payload: Any = json.loads(body)
    except ValueError:
        return "malformed"
    if not isinstance(payload, dict) or payload.get("format") != "tine-webhook/1":
        return "malformed"
    return "valid"


def verify_case(value: dict[str, Any]) -> dict[str, Any]:
    """A conformance ``webhook.verify`` input -> ``{"ok", "class"}``."""
    try:
        body = base64.b64decode(value["body_b64"], validate=True)
        keys = {kid: _unb64url(raw) for kid, raw in value["keys"].items()}
        kind = classify(body, value["header"], keys, value["now"], value["window"])
    except (KeyError, TypeError, ValueError, AttributeError, binascii.Error):
        kind = "malformed"
    return {"class": kind, "ok": kind == "valid"}


__all__ = ["classify", "verify_case"]
