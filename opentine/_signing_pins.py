"""Ed25519 key fingerprints, and pinning a trust-on-first-use check to one.

``--trust-embedded-key`` takes the key from the signature block itself, and
neither ``tine verify`` nor ``tine repo-verify`` said which key that was: an
artifact re-signed by someone else under the same ``signer``/``key_id`` labels
printed exactly what the genuine one printed. Every Ed25519 verdict now names
its key by fingerprint (``sha256:`` + the SHA-256 of the 32 raw key bytes), and
``--pin FINGERPRINT`` turns TOFU into a check against keys the operator chose:
a key not pinned is ``mismatch``, and a pinned one is ``verified``.

The full digest is the pin. A 16-hex prefix is 64 bits, which a key grinder can
match; a pin shorter than the digest is refused rather than trusted.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
from collections.abc import Iterable
from typing import Any

from opentine._signing_keys import SignatureError, coerce_ed25519_public
from opentine._signing_verdicts import lower_hex
from opentine._signing_verify import SignatureResult

_PIN = re.compile(r"(?:sha256:)?([0-9a-f]{64})")


def key_fingerprint(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def normalize_pin(value: str) -> str:
    match = _PIN.fullmatch(value.strip().lower()) if isinstance(value, str) else None
    if match is None:
        raise SignatureError(
            f"--pin {value!r} is not a key fingerprint: give the full sha256:<64 hex> "
            "that tine verify / tine repo-verify print"
        )
    return f"sha256:{match.group(1)}"


def normalize_pins(values: Iterable[str] | None) -> frozenset[str]:
    return frozenset(normalize_pin(value) for value in values or ())


def used_key_fingerprint(block: Any, public_key: Any | None = None) -> str | None:
    """The fingerprint of the Ed25519 key a verdict on *block* rests on, if any.

    The operator's ``--pubkey`` when given (an embedded key must equal it to
    verify), otherwise the block's own embedded key. ``None`` for HMAC.
    """
    if not isinstance(block, dict) or block.get("alg") != "ed25519":
        return None
    if public_key is not None:
        try:
            return key_fingerprint(coerce_ed25519_public(public_key).public_bytes_raw())
        except (SignatureError, TypeError, ValueError):
            return None
    embedded = block.get("public_key")
    return key_fingerprint(bytes.fromhex(embedded)) if lower_hex(embedded, 64) else None


def apply_pins(
    result: SignatureResult, fingerprint: str | None, pins: frozenset[str]
) -> SignatureResult:
    """*result* gated on *pins*: unpinned keys fail, a pinned TOFU key verifies."""
    if not pins or not result.ok:
        return result
    if fingerprint not in pins:
        named = fingerprint or "no Ed25519 key"
        return dataclasses.replace(
            result, ok=False, state="mismatch", reason=f"{named} is not a pinned key"
        )
    return dataclasses.replace(result, state="verified", reason="ok (pinned key)")


__all__ = [
    "apply_pins",
    "key_fingerprint",
    "normalize_pin",
    "normalize_pins",
    "used_key_fingerprint",
]
