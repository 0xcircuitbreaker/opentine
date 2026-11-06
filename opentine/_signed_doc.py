"""``tine-sig/3`` blocks over a JSON document that is not a run (0.39).

A verify report (``tine-verify-report/2``) and a custody record are signed with
the same block shape, header and fail-closed verdict as a v4 artifact
(``_signing_verify``), but over their own domain-separated message::

    <domain prefix> + JCS({"body": <document without its unsigned fields>,
                           "header": <the signature header>})

The prefix names what was signed (``opentine.verify-report.v2:``,
``opentine.custody.v1:``), so a signature over one kind never verifies as
another, nor as a run. Ed25519 only: these documents are meant to be checked
by a stranger holding the public key.
"""

from __future__ import annotations

from typing import Any

from opentine._signing_keys import SignatureError
from opentine._signing_v4 import SCHEME_V3
from opentine._signing_verify import HEADER_KEYS, SignatureResult, sign_block, verify_block
from opentine.kernel import KernelError, canonical_json


def message(domain: bytes, body: dict[str, Any], header: dict[str, Any]) -> bytes:
    view = {"body": body, "header": {key: header.get(key) for key in HEADER_KEYS}}
    try:
        return domain + canonical_json(view)
    except KernelError as exc:
        raise SignatureError(f"document cannot be canonicalized: {exc}") from exc


def sign(
    domain: bytes,
    body: dict[str, Any],
    private_key: Any,
    *,
    signer: str | None = None,
    signed_at: str | None = None,
    key_id: str | None = None,
) -> dict[str, Any]:
    """One Ed25519 ``tine-sig/3`` block over *body* under *domain*."""
    return sign_block(
        lambda header: message(domain, body, header),
        private_key,
        algorithm="ed25519",
        scheme=SCHEME_V3,
        key_id=key_id,
        signer=signer,
        signed_at=signed_at,
        subject="document",
    )


def verify(
    domain: bytes,
    body: dict[str, Any],
    block: Any,
    *,
    public_key: Any | None = None,
) -> SignatureResult:
    """The verdict for *block*; without *public_key* the embedded key is trusted (TOFU)."""
    if isinstance(block, dict) and block.get("alg") != "ed25519":
        return SignatureResult(False, "error", None, None, None, None, "Ed25519 only")
    return verify_block(
        block,
        lambda header: message(domain, body, header),
        schemes=(SCHEME_V3,),
        subject="document",
        public_key=public_key,
        trust_embedded=public_key is None,
    )


def basis(block: Any, public_key: Any | None) -> str:
    """What a passing verdict rests on: a supplied key, or only the embedded one."""
    from opentine._signing_pins import key_fingerprint

    raw = block.get("public_key") if isinstance(block, dict) else None
    try:
        fingerprint = key_fingerprint(bytes.fromhex(raw)) if isinstance(raw, str) else "?"
    except (TypeError, ValueError):
        fingerprint = "?"
    if public_key is not None:
        return f"supplied key {fingerprint}"
    return f"embedded key {fingerprint} (trust on first use)"


__all__ = ["basis", "message", "sign", "verify"]
