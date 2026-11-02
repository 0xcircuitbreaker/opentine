"""Authenticity signatures for legacy .tine artifacts (tine-sig/1, tine-sig/2).

New signatures are written at ``tine-sig/2``, which signs every ``metadata`` key
except ``integrity``; ``tine-sig/1`` signed only a curated metadata allowlist and
is still verified unchanged. See ``_signing_view`` for what each scheme covers.

The keyed algorithms, the header shape and the ``SignatureResult`` verdict this
module returns are shared with v3 attestation signing (``attest_signing``) and
live in ``_signing_verify``; only the signed view and the scheme are local here.
"""

from __future__ import annotations

from typing import Any

from opentine._format_v4 import is_v4_artifact, strict_v4, warn_legacy
from opentine._signing_keys import (
    HAS_ED25519,
    SignatureError,
    ed25519_private_from_file,
    ed25519_public_from_file,
    generate_ed25519,
    hmac_key_from_env,
    hmac_key_from_file,
)
from opentine._signing_verify import (
    MIN_HMAC_KEY_BYTES,
    SignatureResult,
    sign_block,
    verify_block,
)
from opentine._signing_view import (
    DOMAIN_PREFIX,
    SCHEME_V1,
    SCHEME_V2,
    SCHEMES,
)
from opentine._signing_view import (
    signed_message as _message,
)

#: Kept as the pre-0.7.1 spelling of the v1 constant; new signatures use SCHEME_V2.
SCHEME = SCHEME_V1


def sign_artifact(
    data: dict[str, Any],
    key: Any,
    *,
    algorithm: str = "hmac-sha256",
    key_id: str | None = None,
    signer: str | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    if is_v4_artifact(data):  # a v4 document is always signed with tine-sig/3
        from opentine._signing_v4 import sign_artifact_v4

        return sign_artifact_v4(
            data, key, algorithm=algorithm, key_id=key_id, signer=signer, signed_at=signed_at
        )
    if strict_v4():
        raise SignatureError(
            "tine-sig/2 is not written when OPENTINE_FORMAT=4; v4 artifacts are signed "
            "with tine-sig/3 (opentine._signing_v4)"
        )
    warn_legacy()  # a v2 document can only carry the deprecated tine-sig/2
    return sign_block(
        lambda header: _message(data, header),
        key,
        algorithm=algorithm,
        scheme=SCHEME_V2,
        key_id=key_id,
        signer=signer,
        signed_at=signed_at,
        subject="artifact",
    )


def verify_artifact(
    data: dict[str, Any],
    *,
    hmac_key: bytes | None = None,
    public_key: Any | None = None,
    trust_embedded: bool = False,
) -> SignatureResult:
    if not isinstance(data, dict):
        return SignatureResult(
            False, "error", None, None, None, None, "artifact root is not an object"
        )
    if is_v4_artifact(data):
        from opentine._signing_v4 import verify_artifact_v4

        return verify_artifact_v4(
            data, hmac_key=hmac_key, public_key=public_key, trust_embedded=trust_embedded
        )
    metadata = data.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        return SignatureResult(
            False, "error", None, None, None, None, "artifact metadata is not an object"
        )
    integrity = (metadata or {}).get("integrity")
    if integrity is not None and not isinstance(integrity, dict):
        return SignatureResult(
            False, "error", None, None, None, None, "artifact integrity is not an object"
        )
    return verify_block(
        (integrity or {}).get("signature"),
        lambda header: _message(data, header),
        schemes=SCHEMES,
        subject="artifact",
        hmac_key=hmac_key,
        public_key=public_key,
        trust_embedded=trust_embedded,
    )


__all__ = [
    "DOMAIN_PREFIX",
    "HAS_ED25519",
    "MIN_HMAC_KEY_BYTES",
    "SCHEMES",
    "SCHEME_V1",
    "SCHEME_V2",
    "SignatureError",
    "SignatureResult",
    "ed25519_private_from_file",
    "ed25519_public_from_file",
    "generate_ed25519",
    "hmac_key_from_env",
    "hmac_key_from_file",
    "sign_artifact",
    "verify_artifact",
]
