"""Signed webhook payloads, ``tine-webhook/1`` (0.45.1, SPEC 8.13).

A delivery's body is canonical JSON (sorted keys, no whitespace, ASCII only).
The ``OpenTine-Signature`` header is ``t=<unix seconds>,kid=<key id>,sig=<sig>``
where ``sig`` is the unpadded base64url Ed25519 signature over::

    b"opentine-webhook/1\\n" + str(t) + b"\\n" + body

and the key id is ``ed25519:`` plus the first 16 hex digits of SHA-256 over the
raw 32-byte public key. A receiver checks ``|now - t| <= window`` (300 s by
default) and the signature with a key it pinned from ``GET /v1/capabilities``
(``webhooks.keys``). The timestamp is re-signed on every retry; the body, and
its ``delivery`` id a receiver de-duplicates by, is not.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

FORMAT = "tine-webhook/1"
DOMAIN = b"opentine-webhook/1\n"
HEADER = "OpenTine-Signature"
DELIVERY_HEADER = "OpenTine-Delivery"
REPLAY_WINDOW = 300
MAX_BODY = 256 * 1024
_FIELDS = re.compile(r"^t=([0-9]{1,12}),kid=(ed25519:[0-9a-f]{16}),sig=([A-Za-z0-9_-]{86})$")


class WebhookSignatureError(ValueError):
    """A refused delivery; ``kind``: malformed, stale, unknown-key or bad-signature."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id(public_raw: bytes) -> str:
    return "ed25519:" + hashlib.sha256(public_raw).hexdigest()[:16]


def canonical_body(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def signing_input(timestamp: int, body: bytes) -> bytes:
    return DOMAIN + str(int(timestamp)).encode("ascii") + b"\n" + body


def sign(key: Ed25519PrivateKey, body: bytes, timestamp: int | None = None) -> str:
    """The ``OpenTine-Signature`` header value for *body* at *timestamp*."""
    when = int(time.time()) if timestamp is None else int(timestamp)
    kid = key_id(key.public_key().public_bytes_raw())
    return f"t={when},kid={kid},sig={b64url(key.sign(signing_input(when, body)))}"


def public_keys(entries: list[dict[str, str]]) -> dict[str, bytes]:
    """``caps.webhooks.keys`` -> ``{kid: raw public key}``, refusing a mislabelled id."""
    keys: dict[str, bytes] = {}
    for entry in entries:
        raw = unb64url(entry["public_key"])
        if entry.get("alg") != "ed25519" or len(raw) != 32 or key_id(raw) != entry["kid"]:
            raise ValueError("webhook key entry does not match its key id")
        keys[entry["kid"]] = raw
    return keys


def verify(
    body: bytes,
    header: str,
    keys: dict[str, bytes],
    *,
    now: float | None = None,
    window: int = REPLAY_WINDOW,
) -> dict[str, Any]:
    """The payload of a delivery that verifies; :class:`WebhookSignatureError` otherwise."""
    match = _FIELDS.fullmatch(header.strip())
    if match is None or len(body) > MAX_BODY:
        raise WebhookSignatureError("malformed", "malformed signature header or oversized body")
    timestamp, kid, sig = int(match.group(1)), match.group(2), match.group(3)
    if abs((time.time() if now is None else now) - timestamp) > window:
        raise WebhookSignatureError("stale", "delivery is outside the replay window")
    if kid not in keys:
        raise WebhookSignatureError("unknown-key", f"no pinned webhook key {kid}")
    try:
        Ed25519PublicKey.from_public_bytes(keys[kid]).verify(
            unb64url(sig), signing_input(timestamp, body)
        )
    except (InvalidSignature, ValueError) as exc:
        raise WebhookSignatureError("bad-signature", "webhook signature does not verify") from exc
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise WebhookSignatureError("malformed", "body is not JSON") from exc
    if not isinstance(payload, dict) or payload.get("format") != FORMAT:
        raise WebhookSignatureError("malformed", f"body is not a {FORMAT} payload")
    return payload


__all__ = [
    "DELIVERY_HEADER",
    "FORMAT",
    "HEADER",
    "REPLAY_WINDOW",
    "WebhookSignatureError",
    "canonical_body",
    "key_id",
    "public_keys",
    "sign",
    "signing_input",
    "verify",
]
