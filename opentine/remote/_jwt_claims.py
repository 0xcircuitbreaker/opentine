"""Registered-claim checks for ``JWTVerifier`` (iss, aud, azp, exp, nbf).

``azp`` (authorized party) used to have to equal the audience whenever present,
which rejected the ordinary access token an IdP issues to a client for this API
(``aud`` = the API, ``azp`` = the client). It is now accepted when absent with a
single audience, when it is the audience, or when it is one of the verifier's
``authorized_parties`` -- the client ids the operator lists. A token with several
audiences must still name its ``azp`` (OpenID Connect Core 3.1.3.7).
"""

from __future__ import annotations

import math
from typing import Any

from opentine.remote._jwks import OIDCError


def _finite(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


def validate_claims(verifier: Any, claims: dict[str, Any]) -> None:
    if claims.get("iss") != verifier.issuer:
        raise OIDCError("JWT issuer mismatch")
    audience = claims.get("aud")
    allowed = audience if isinstance(audience, list) else [audience]
    if not all(isinstance(item, str) for item in allowed):
        raise OIDCError("JWT audience must be a string or list of strings")
    if verifier.audience not in allowed:
        raise OIDCError("JWT audience mismatch")
    party = claims.get("azp")
    parties = {verifier.audience, *getattr(verifier, "authorized_parties", ())}
    if (len(allowed) > 1 or party is not None) and party not in parties:
        raise OIDCError("JWT authorized party mismatch")
    now = verifier.now()
    if not _finite(now):
        raise OIDCError("JWT verifier clock is invalid")
    expiry = claims.get("exp")
    if not _finite(expiry) or now >= expiry + verifier.leeway:
        raise OIDCError("JWT is expired or missing 'exp'")
    not_before = claims.get("nbf")
    if not_before is not None and (not _finite(not_before) or now < not_before - verifier.leeway):
        raise OIDCError("JWT is not yet valid")
