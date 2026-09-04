"""Cryptographic signatures for v3 attestations (``tine-attest/1``).

``repository.ops.attest`` has always had a ``signature`` slot and nothing ever
filled it, so a v3 attestation was an unauthenticated claim: the ``signer`` was
a self-asserted label. These two functions fill that slot and check it, over the
signed view in ``_attest_view`` and with the algorithms, header and verdict
vocabulary in ``_signing_verify`` — the same ones ``signing`` uses for a
``.tine`` artifact.

Two rules keep the verdict honest:

* **Signing is opt-in and additive.** ``Repo.attest`` without a key writes the
  byte-identical unsigned object it always wrote (``"signature": null``), and
  that object verifies as ``unsigned`` — never as ``verified``.
* **The header's ``signer`` is the payload's ``signer``.** There is one identity
  in an attestation, so ``sign_attestation`` reads it off the payload rather
  than accepting a second one that could disagree with the claim being signed.
"""

from __future__ import annotations

from typing import Any

from opentine._attest_view import ATTEST_SCHEMES, SCHEME_ATTEST_V1, SIGNATURE_KEY
from opentine._attest_view import (
    signed_message as _message,
)
from opentine._signing_keys import SignatureError
from opentine._signing_verify import SignatureResult, sign_block, verify_block


def sign_attestation(
    payload: dict[str, Any],
    key: Any,
    *,
    algorithm: str = "hmac-sha256",
    key_id: str | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Return the ``tine-attest/1`` signature block for an attestation *payload*.

    *payload* is the attestation body as it will be **stored** (any
    ``signature`` key in it is ignored, being what this returns). The caller
    stores the returned block at that key; ``verify_attestation`` recomputes the
    same view from the stored object.
    """
    if not isinstance(payload, dict):
        raise SignatureError("attestation payload must be an object")
    signer = payload.get("signer")
    if not isinstance(signer, str) or not signer:
        raise SignatureError("attestation signer must be a non-empty string")
    return sign_block(
        lambda header: _message(payload, header),
        key,
        algorithm=algorithm,
        scheme=SCHEME_ATTEST_V1,
        key_id=key_id,
        signer=signer,
        signed_at=signed_at,
        subject="attestation",
    )


def verify_attestation(
    payload: Any,
    *,
    hmac_key: bytes | None = None,
    public_key: Any | None = None,
    trust_embedded: bool = False,
) -> SignatureResult:
    """Check the signature on a stored attestation payload, fail-closed.

    ``unsigned`` for an attestation with no block, ``no-key`` for one signed
    under a key this caller does not hold, ``mismatch`` for any edit to the
    target, claim, signer, evidence or signed header, ``verified`` only when a
    supplied key agrees with the stored view.
    """
    if not isinstance(payload, dict):
        return SignatureResult(
            False, "error", None, None, None, None, "attestation payload is not an object"
        )
    return verify_block(
        payload.get(SIGNATURE_KEY),
        lambda header: _message(payload, header),
        schemes=ATTEST_SCHEMES,
        subject="attestation",
        hmac_key=hmac_key,
        public_key=public_key,
        trust_embedded=trust_embedded,
    )


__all__ = [
    "ATTEST_SCHEMES",
    "SCHEME_ATTEST_V1",
    "SignatureResult",
    "sign_attestation",
    "verify_attestation",
]
