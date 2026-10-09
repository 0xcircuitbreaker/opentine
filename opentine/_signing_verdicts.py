"""The keyed half of a signature verdict: does the supplied key agree?

Split out of ``_signing_verify`` (which owns the block shape and the verdict
vocabulary) for the module line cap. Every branch returns through the caller's
``result`` so the state vocabulary stays in one place.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from opentine._signing_keys import SignatureError
from opentine._signing_keys import coerce_ed25519_public as _coerce_ed25519_public

if TYPE_CHECKING:
    from opentine._signing_verify import SignatureResult

#: Signed values and keys are lowercase hex as ``sign_block`` writes them.
#: ``is_hex`` accepts anything ``int(x, 16)`` does -- upper case, ``_``, ``0x`` --
#: and ``bytes.fromhex`` then decoded an upper-case re-spelling to the same
#: bytes, so one signature verified under several object ids.
_LOWER_HEX = re.compile(r"[0-9a-f]+")

MIN_HMAC_KEY_BYTES = 16


def require_strong_hmac_key(key: Any) -> None:
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise SignatureError("HMAC key must be non-empty bytes")
    if len(key) < MIN_HMAC_KEY_BYTES:
        raise SignatureError(
            f"HMAC key too short ({len(key)} bytes); use at least {MIN_HMAC_KEY_BYTES}"
        )


def lower_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and bool(_LOWER_HEX.fullmatch(value))


def hmac_verdict(
    message: bytes, value: str, hmac_key: bytes | None, result: Callable[..., SignatureResult]
) -> SignatureResult:
    if hmac_key is None:
        return result(False, "no-key", "HMAC signature present but no key supplied")
    try:
        require_strong_hmac_key(hmac_key)
    except SignatureError as exc:
        return result(False, "error", str(exc))
    expected = hmac.new(bytes(hmac_key), message, hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(expected, value)
    return result(
        valid, "verified" if valid else "mismatch", "ok" if valid else "signature mismatch"
    )


def ed25519_verdict(
    message: bytes,
    value: str,
    block: dict[str, Any],
    public_key: Any | None,
    trust_embedded: bool,
    result: Callable[..., SignatureResult],
) -> SignatureResult:
    embedded = block.get("public_key")
    if embedded is not None and not lower_hex(embedded, 64):
        return result(False, "error", "malformed ed25519 public key")
    try:
        if public_key is not None:
            public = _coerce_ed25519_public(public_key)
            state = "verified"
            # The embedded key is part of the stored object: one naming another
            # key than the one that verified was a second oid for one signature.
            if embedded is not None and embedded != public.public_bytes_raw().hex():
                return result(False, "mismatch", "embedded public key is not the trusted key")
        elif trust_embedded and embedded is not None:
            public = _coerce_ed25519_public(embedded)  # refuses a small-order key
            state = "verified-tofu"
        elif trust_embedded:
            raise SignatureError("malformed embedded public key")
        else:
            return result(False, "no-key", "ed25519 signature present but no trusted public key")
    except (SignatureError, TypeError, ValueError) as exc:
        weak = "small order" in str(exc)
        return result(False, "error", str(exc) if weak else "malformed ed25519 public key")
    try:
        public.verify(bytes.fromhex(value), message)
    except Exception:
        return result(False, "mismatch", "signature mismatch")
    return result(True, state, "ok")
