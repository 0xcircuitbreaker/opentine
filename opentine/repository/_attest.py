"""Writing and verifying attestations, the one v3 object that carries a signature.

Split out of ``ops`` for the module line cap, and because signing is the part of
``attest`` with rules of its own:

**The signature covers the payload as stored.** ``Repo.put`` redacts credential
shaped fields on the way in, so a claim holding ``{"api_key": "sk-…"}`` is
stored as ``[REDACTED]``. Signing the caller's dict would therefore sign bytes
no reader ever sees, and every such attestation would verify as ``mismatch``.
The redaction is idempotent, so this module applies it *before* signing and lets
``put`` apply it again to the same value.

**Unsigned stays byte-identical.** With no key, the payload written is exactly
the one 0.3.0-0.8.1 wrote — ``"signature": null`` included — so existing
repositories keep their attestation oids and re-attesting the same claim still
lands on the same object. Signing is opt-in; a missing signature verifies as
``unsigned``, never as ``verified``.

**One prepared block or one key, never both.** ``signature=`` (a block prepared
elsewhere, the pre-0.9.0 slot) and ``key=`` (sign here) fill the same field, so
passing both is refused rather than silently resolved.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentine._v3_guards import guarded_redaction
from opentine.attest_signing import sign_attestation, verify_attestation
from opentine.kernel import parse_oid
from opentine.repository._access import get_object as _get
from opentine.repository._associations import MAX_ASSOCIATION_SCAN, associated_map

if TYPE_CHECKING:
    from opentine._signing_verify import SignatureResult
    from opentine.repository.store import Repo


def attest(
    repo: Repo,
    target_id: str,
    claim: dict[str, Any],
    *,
    signer: str,
    signature: dict[str, Any] | None = None,
    evidence_ids: list[str] | None = None,
    key: Any | None = None,
    algorithm: str = "hmac-sha256",
    key_id: str | None = None,
    signed_at: str | None = None,
) -> str:
    if signature is not None and key is not None:
        raise ValueError("pass either a prepared signature or a signing key, not both")
    payload: dict[str, Any] = {
        "claim": claim,
        "evidence_ids": list(evidence_ids or []),
        "signer": signer,
        "target_id": target_id,
    }
    if key is not None:
        # The bytes ``put`` will store, so the signature covers what readers read.
        payload = guarded_redaction(payload, where="v3 'attestation'")
        signature = sign_attestation(
            payload, key, algorithm=algorithm, key_id=key_id, signed_at=signed_at
        )
    return repo.put("attestation", {**payload, "signature": signature})


def verify_attestation_object(
    repo: Repo,
    oid: str,
    *,
    hmac_key: bytes | None = None,
    public_key: Any | None = None,
    trust_embedded: bool = False,
) -> SignatureResult:
    """Verify the signature on one stored attestation, by object id."""
    if parse_oid(oid)[0] != "attestation":
        raise ValueError(f"{oid} is not an attestation id")
    return verify_attestation(
        _get(repo, oid).payload(),
        hmac_key=hmac_key,
        public_key=public_key,
        trust_embedded=trust_embedded,
    )


def attestations_for(repo: Repo, run_id: str) -> tuple[str, ...]:
    """The attestation ids targeting *run_id*, sorted, using the bounded scan."""
    found = associated_map(repo, [run_id], MAX_ASSOCIATION_SCAN).get(run_id) or []
    return tuple(sorted(oid for oid in found if oid.startswith("attestation:")))
