"""The verdict vocabulary and the keyed half every OpenTine signature shares.

Two signature families exist, and they differ only in *what* they sign:

* ``tine-sig/1`` / ``tine-sig/2`` (``signing`` + ``_signing_view``) over a legacy
  ``.tine`` artifact, stored at ``metadata.integrity.signature``.
* ``tine-attest/1`` (``attest_signing`` + ``_attest_view``) over a v3
  attestation, stored at the attestation payload's ``signature`` key.

The algorithms, the header shape, the strong-key floor, and the five-state
verdict are identical for both, so they live here once. A second copy is how the
two families would come to give different answers to "is this signed?" — the
question this module exists to answer the same way every time.

``SignatureResult.state`` is that vocabulary, and it is **fail-closed**:
``verified`` (and Ed25519's ``verified-tofu``) are the only states carrying
``ok=True``.

* ``unsigned`` — no signature block at all. Never an error, never verified.
* ``no-key``   — a block is present but the caller supplied no key for its
                 algorithm, so nothing was checked.
* ``mismatch`` — a key was applied and disagreed. The tamper verdict.
* ``error``    — the block, its scheme, or the signed content is malformed.

Every branch below returns one of those rather than raising, so a caller that
only checks ``ok`` cannot accidentally read a refusal as a pass.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from opentine._signing_keys import (
    HAS_ED25519,
    SignatureError,
)
from opentine._signing_keys import (
    load_ed25519_private as _load_ed25519_private,
)
from opentine._signing_verdicts import (
    MIN_HMAC_KEY_BYTES,
    ed25519_verdict,
    hmac_verdict,
    lower_hex,
    require_strong_hmac_key,
)

#: The two keyed algorithms, and the hex length each one's value must have.
VALUE_LENGTHS = {"hmac-sha256": 64, "ed25519": 128}
ALGORITHMS = frozenset(VALUE_LENGTHS)

#: The signed header, in every scheme of both families. The scheme string is one
#: of these keys, so a message under one scheme can never equal a message under
#: another even over identical content.
HEADER_KEYS = ("alg", "key_id", "scheme", "signed_at", "signer")


#: Everything a stored block may hold: the header, the value, Ed25519's key.
_BLOCK_KEYS = frozenset((*HEADER_KEYS, "value", "public_key"))


#: ``header -> the exact bytes signed``. The one thing each family supplies.
MessageBuilder = Callable[[dict[str, Any]], bytes]


@dataclass(frozen=True)
class SignatureResult:
    ok: bool
    state: str
    algorithm: str | None
    key_id: str | None
    signer: str | None
    signed_at: str | None
    reason: str


def sign_block(
    build_message: MessageBuilder,
    key: Any,
    *,
    algorithm: str,
    scheme: str,
    key_id: str | None = None,
    signer: str | None = None,
    signed_at: str | None = None,
    subject: str = "artifact",
) -> dict[str, Any]:
    """Build the signature block for ``build_message``'s signed view.

    ``None`` header values are dropped from the *stored* block but stay in the
    signed header, so an absent ``key_id`` is signed as absent and cannot be
    added afterwards without the signature going ``mismatch``.
    """
    if algorithm not in ALGORITHMS:
        raise SignatureError(f"unsupported signature algorithm {algorithm!r}")
    if any(item is not None and not isinstance(item, str) for item in (key_id, signer, signed_at)):
        raise SignatureError("signature metadata values must be strings")
    if algorithm == "hmac-sha256":
        require_strong_hmac_key(key)
        private = None
    else:
        private = _load_ed25519_private(key)
    header = {
        "alg": algorithm,
        "key_id": key_id,
        "scheme": scheme,
        "signed_at": signed_at,
        "signer": signer,
    }
    try:
        message = build_message(header)
    except SignatureError:
        raise
    except (AttributeError, RecursionError, TypeError, ValueError) as exc:
        raise SignatureError(f"{subject} content cannot be signed") from exc
    block = {name: value for name, value in header.items() if value is not None}
    if algorithm == "hmac-sha256":
        block["value"] = hmac.new(bytes(key), message, hashlib.sha256).hexdigest()
    else:
        block["value"] = private.sign(message).hex()
        block["public_key"] = private.public_key().public_bytes_raw().hex()
    return block


def verify_block(
    block: Any,
    build_message: MessageBuilder,
    *,
    schemes: tuple[str, ...],
    subject: str = "artifact",
    hmac_key: bytes | None = None,
    public_key: Any | None = None,
    trust_embedded: bool = False,
) -> SignatureResult:
    """Check one signature block against the content ``build_message`` projects."""
    if block is None:
        return SignatureResult(False, "unsigned", None, None, None, None, "no signature present")
    if not isinstance(block, dict):
        return SignatureResult(
            False, "error", None, None, None, None, f"{subject} signature is not an object"
        )
    algorithm = block.get("alg")
    raw_optional = (block.get("key_id"), block.get("signer"), block.get("signed_at"))
    optional = tuple(item if isinstance(item, str) else None for item in raw_optional)
    details = (algorithm if isinstance(algorithm, str) else None, *optional)

    def result(ok: bool, state: str, reason: str) -> SignatureResult:
        return SignatureResult(ok, state, *details, reason)

    # Each block is verified under the scheme it names: a v1 signature keeps its
    # (narrower) v1 signed view forever, and only a v2 block gets v2's coverage.
    if block.get("scheme") not in schemes:
        return result(False, "error", "unsupported signature scheme")
    # One key, chosen by the operator: given several, the block's own ``alg``
    # would pick which of them is trusted.
    if (hmac_key is not None) + (public_key is not None) + bool(trust_embedded) > 1:
        return result(False, "error", "pass exactly one verification key")
    # A block is signed byte-for-byte as sign_block writes it. Unknown keys and
    # re-spelled hex verified anyway, so one signature minted many object ids.
    if set(block) - _BLOCK_KEYS or (algorithm != "ed25519" and "public_key" in block):
        return result(False, "error", "malformed signature header")
    if not isinstance(algorithm, str) or any(
        item is not None and not isinstance(item, str) for item in raw_optional
    ):
        return result(False, "error", "malformed signature header")
    if algorithm not in ALGORITHMS:
        return result(False, "error", "unsupported signature algorithm")
    value = block.get("value")
    if not lower_hex(value, VALUE_LENGTHS[algorithm]):
        return result(False, "error", "malformed signature value")
    header = {name: block.get(name) for name in HEADER_KEYS}
    header["alg"] = algorithm
    try:
        message = build_message(header)
    except (RecursionError, SignatureError, TypeError, ValueError):
        return result(False, "error", f"malformed signed {subject} content")
    if algorithm == "hmac-sha256":
        return hmac_verdict(message, value, hmac_key, result)
    if not HAS_ED25519:
        return result(False, "error", "ed25519 requires the 'cryptography' extra")
    return ed25519_verdict(message, value, block, public_key, trust_embedded, result)


__all__ = [
    "ALGORITHMS",
    "HEADER_KEYS",
    "MIN_HMAC_KEY_BYTES",
    "SignatureResult",
    "require_strong_hmac_key",
    "sign_block",
    "verify_block",
]
