"""Scheme-versioned signed views for ``.tine`` signatures.

``signing`` computes one keyed MAC / signature over the canonical bytes of a
*signed view* — a stable projection of the artifact. Which parts of the artifact
that projection covers is the scheme's whole meaning, so it is versioned:

* ``tine-sig/1`` (0.3.0-0.7.0) covers the body, the signature header, and a
  curated allowlist of ``metadata`` keys. The allowlist is frozen forever, not
  merely stable: it is the definition older signatures were computed against.
* ``tine-sig/2`` (0.7.1+) covers the body, the header, and *every* ``metadata``
  key except ``integrity``. Tags and application-added metadata are inside the
  signature, which they never were under v1.

This lives beside ``signing`` rather than inside it so the dispatch has room to
grow without pushing that module past the 250-line architecture gate.
"""

from __future__ import annotations

from typing import Any

from opentine._canon import _canonical_bytes
from opentine._signing_keys import SignatureError

#: The legacy scheme. Still verified (and only verified — never written) so that
#: genuine 0.3.0-0.7.0 signatures keep verifying byte-identically.
SCHEME_V1 = "tine-sig/1"

#: The scheme new signatures are written at.
SCHEME_V2 = "tine-sig/2"

#: Every scheme this build can verify.
SCHEMES = (SCHEME_V1, SCHEME_V2)

#: One prefix for both schemes: the scheme string itself is inside the signed
#: header, so a v1 message and a v2 message over the same artifact already
#: differ in their canonical bytes and cannot be confused for one another.
DOMAIN_PREFIX = b"opentine.signature.v1:"

#: The ``metadata`` keys ``tine-sig/1`` signs. FROZEN — adding a key here would
#: retroactively falsify genuine older signatures over artifacts carrying it
#: (the reason ``fork_reason`` is absent: 0.3.0 wrote it but did not sign it).
#: New coverage goes to ``tine-sig/2``, which signs everything, not to this list.
_SIGNED_METADATA_KEYS = (
    "model_info",
    "system_prompt",
    "user_prompt",
    "forked_from",
    "fork_point",
    "warnings",
    "replay",
    "context",
    "next_harness",
    "migration",
    # "fork" (the 0.4.0 fork-identity record) was safe to add: 0.3.0 never wrote
    # metadata["fork"], so it changed no existing signature.
    "fork",
)


def _signed_metadata(scheme: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    if scheme == SCHEME_V2:
        # Everything but "integrity", which holds the signature block being
        # computed (self-reference) alongside the unkeyed digest, itself taken
        # over body keys this view already covers in full.
        return {key: value for key, value in metadata.items() if key != "integrity"}
    return {key: metadata.get(key) for key in _SIGNED_METADATA_KEYS if key in metadata}


def signed_view(data: dict[str, Any], header: dict[str, Any]) -> dict[str, Any]:
    """The canonicalizable projection of ``data`` this ``header``'s scheme signs."""
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise SignatureError("artifact metadata must be an object")
    return {
        "body": {key: value for key, value in data.items() if key != "metadata"},
        "header": {
            "alg": header.get("alg"),
            "key_id": header.get("key_id"),
            "scheme": header.get("scheme"),
            "signed_at": header.get("signed_at"),
            "signer": header.get("signer"),
        },
        "metadata": _signed_metadata(header.get("scheme"), metadata),
    }


def signed_message(data: dict[str, Any], header: dict[str, Any]) -> bytes:
    return DOMAIN_PREFIX + _canonical_bytes(signed_view(data, header))


__all__ = [
    "DOMAIN_PREFIX",
    "SCHEMES",
    "SCHEME_V1",
    "SCHEME_V2",
    "signed_message",
    "signed_view",
]
