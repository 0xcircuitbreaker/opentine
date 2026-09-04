"""The signed view for ``tine-attest/1``: what a v3 attestation signature covers.

An attestation is the object that says *someone approved this run*. Before
0.9.0 its ``signer`` was a bare label — anyone who could write to the repository
could write ``signer: security-team`` and nothing could tell. ``tine-attest/1``
binds that label to a key by signing a canonical projection of the attestation,
exactly the way ``_signing_view`` does for a ``.tine`` artifact.

**What the view covers** (everything that gives the attestation meaning):

* every key of the attestation payload except ``signature`` — today that is
  ``target_id`` (*which run*), ``claim`` (*what is asserted*), ``signer``
  (*whose assertion*) and ``evidence_ids`` (*what backs it*), and tomorrow any
  field a later writer adds, without a new scheme;
* the signature header: ``alg``, ``key_id``, ``scheme``, ``signed_at`` and
  ``signer``, so the algorithm cannot be downgraded, the scheme cannot be
  swapped, and the timestamp cannot be moved after the fact.

**What it deliberately excludes**, and why:

* ``signature`` itself — it is the value being computed, so covering it would be
  self-referential. Its *header* is covered separately (above), which is what
  makes the exclusion safe: everything in the block except the opaque ``value``
  (and, for Ed25519, the embedded ``public_key``) is inside the signature.
* the object id and the envelope (``type``/``schema``). The oid is the digest of
  the stored payload *including* the signature, so signing it is impossible by
  construction; it needs no coverage either, because content addressing already
  makes the payload -> oid direction tamper-evident, and the payload is what
  this view signs in full.

The body is taken from the payload as **stored** — after ``Repo.put``'s
redaction — so a claim carrying a credential-shaped field is signed in the form
every reader will see, not in the form the caller passed.
"""

from __future__ import annotations

from typing import Any

from opentine._canon import _canonical_bytes
from opentine._signing_keys import SignatureError
from opentine._signing_verify import HEADER_KEYS

#: The scheme new attestation signatures are written at, and the only one this
#: build verifies. Recorded inside the signed header, so a future
#: ``tine-attest/2`` with wider coverage cannot be confused with a v1 message.
SCHEME_ATTEST_V1 = "tine-attest/1"

#: Every attestation scheme this build can verify.
ATTEST_SCHEMES = (SCHEME_ATTEST_V1,)

#: Distinct from ``_signing_view.DOMAIN_PREFIX``: an artifact signed view and an
#: attestation signed view must never hash to the same message, so no signature
#: can be lifted from one family into the other.
ATTEST_DOMAIN_PREFIX = b"opentine.attestation.v1:"

#: The payload key holding the block, and therefore the one key outside the view.
SIGNATURE_KEY = "signature"


def signed_view(payload: dict[str, Any], header: dict[str, Any]) -> dict[str, Any]:
    """The canonicalizable projection of an attestation *payload* this scheme signs."""
    if not isinstance(payload, dict):
        raise SignatureError("attestation payload must be an object")
    return {
        "body": {key: value for key, value in payload.items() if key != SIGNATURE_KEY},
        "header": {key: header.get(key) for key in HEADER_KEYS},
    }


def signed_message(payload: dict[str, Any], header: dict[str, Any]) -> bytes:
    return ATTEST_DOMAIN_PREFIX + _canonical_bytes(signed_view(payload, header))


__all__ = [
    "ATTEST_DOMAIN_PREFIX",
    "ATTEST_SCHEMES",
    "SCHEME_ATTEST_V1",
    "SIGNATURE_KEY",
    "signed_message",
    "signed_view",
]
