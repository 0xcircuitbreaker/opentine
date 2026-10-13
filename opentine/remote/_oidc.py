"""Standards-correct OIDC/JWT verification (RS256/ES256) over a JWKS.

Validates the JWS signature, issuer, audience, and expiry so the OIDC seam is a
real verifier rather than a trust-everything stub. Network discovery is optional
and dependency-injected (pass a ``fetch`` callable), so the verifier is fully
testable offline with a static JWKS.
"""

from __future__ import annotations

import base64
import json
import math
import time
from collections.abc import Callable
from typing import Any

from opentine.kernel import validate_json_shape
from opentine.remote._jwks import (
    DEFAULT_MAX_KEY_AGE,
    DEFAULT_REFRESH_INTERVAL,
    KeySet,
    OIDCError,
)
from opentine.remote._jwt_claims import validate_claims

#: ``typ`` values an access or ID token may carry (RFC 7519, RFC 9068). Absent is
#: accepted too. Anything else -- ``dpop+jwt``, ``logout+jwt``, ``secevent+jwt`` --
#: is a different kind of JWT the same issuer signs, never a bearer credential.
_TOKEN_TYPES = frozenset({"jwt", "at+jwt"})


def _b64url(segment: str) -> bytes:
    if not isinstance(segment, str) or len(segment) > 1024 * 1024:
        raise OIDCError("malformed JWT segment")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeError, ValueError) as exc:
        raise OIDCError("malformed JWT base64") from exc


def _int(segment: str) -> int:
    return int.from_bytes(_b64url(segment), "big")


def _public_key(jwk: dict[str, Any]):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
        if kty == "EC" and jwk.get("crv") == "P-256":
            numbers = ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), ec.SECP256R1())
            return numbers.public_key()
    except (KeyError, TypeError, ValueError) as exc:
        raise OIDCError("malformed JWK public key") from exc
    raise OIDCError(f"unsupported JWK key type: {kty}/{jwk.get('crv')}")


def _verify_signature(alg: str, jwk: dict[str, Any], message: bytes, signature: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

    expected_key = "RSA" if alg == "RS256" else "EC" if alg == "ES256" else None
    if expected_key is None or jwk.get("kty") != expected_key:
        raise OIDCError("JWT algorithm and JWK key type do not match")
    if jwk.get("alg") not in (None, alg) or jwk.get("use") not in (None, "sig"):
        raise OIDCError("JWK is not permitted for this signature algorithm")
    key_ops = jwk.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        raise OIDCError("JWK is not permitted for signature verification")
    public = _public_key(jwk)
    if alg == "RS256" and public.key_size < 2048:
        raise OIDCError("RSA verification keys must be at least 2048 bits")
    try:
        if alg == "RS256":
            public.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "ES256":
            if len(signature) != 64:
                raise OIDCError("malformed ES256 signature")
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            der = utils.encode_dss_signature(r, s)
            public.verify(der, message, ec.ECDSA(hashes.SHA256()))
        else:
            raise OIDCError(f"unsupported signature algorithm: {alg}")
    except InvalidSignature as exc:
        raise OIDCError("JWT signature verification failed") from exc
    except (TypeError, ValueError) as exc:
        raise OIDCError("malformed JWT signature") from exc


def _json_object(segment: str, label: str) -> dict[str, Any]:
    try:
        raw = _b64url(segment)
        validate_json_shape(raw, max_tokens=50_000)
        value = json.loads(raw)
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise OIDCError(f"malformed JWT {label}") from exc
    if not isinstance(value, dict):
        raise OIDCError(f"JWT {label} must be an object")
    return value


def _document(raw: bytes | str, label: str) -> dict[str, Any]:
    if not isinstance(raw, (bytes, str)) or len(raw) > 4 * 1024 * 1024:
        raise OIDCError(f"OIDC {label} exceeds the document limit")
    try:
        validate_json_shape(raw, max_tokens=100_000)
        value = json.loads(raw)
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise OIDCError(f"malformed OIDC {label}") from exc
    if not isinstance(value, dict):
        raise OIDCError(f"OIDC {label} must be an object")
    return value


class JWTVerifier:
    """Verify an OIDC ID/access token against a JWKS. Usable as the OIDC ``verifier``."""

    def __init__(
        self,
        jwks: dict[str, Any],
        *,
        issuer: str,
        audience: str,
        algorithms: tuple[str, ...] = ("RS256", "ES256"),
        leeway: int = 60,
        now: Callable[[], float] = time.time,
        jwks_fetch: Callable[[], Any] | None = None,
        refresh_interval: float = DEFAULT_REFRESH_INTERVAL,
        max_key_age: float = DEFAULT_MAX_KEY_AGE,
        clock: Callable[[], float] = time.monotonic,
        authorized_parties: tuple[str, ...] = (),
    ):
        #: Client ids (``azp``) accepted besides the audience itself (_jwt_claims).
        if not all(isinstance(party, str) and party for party in authorized_parties):
            raise OIDCError("authorized parties must be non-empty client id strings")
        self.authorized_parties = frozenset(authorized_parties)
        self._key_set = KeySet(
            jwks,
            fetch=jwks_fetch,
            refresh_interval=refresh_interval,
            max_age=max_key_age,
            clock=clock,
        )
        supported = {"RS256", "ES256"}
        if not algorithms or not set(algorithms) <= supported:
            raise OIDCError("JWT algorithms must be a subset of RS256/ES256")
        if (
            not issuer
            or not audience
            or isinstance(leeway, bool)
            or not isinstance(leeway, (int, float))
            or not math.isfinite(leeway)
            or leeway < 0
        ):
            raise OIDCError("issuer, audience, and non-negative leeway are required")
        self.issuer = issuer
        self.audience = audience
        self.algorithms = set(algorithms)
        self.leeway = leeway
        self.now = now

    @property
    def keys(self) -> dict[str, dict[str, Any]]:
        return self._key_set.keys

    @classmethod
    def from_discovery(
        cls, issuer: str, audience: str, fetch: Callable[[str], bytes], **kwargs: Any
    ) -> JWTVerifier:
        if not issuer.startswith("https://"):
            raise OIDCError("OIDC discovery requires an HTTPS issuer")
        config = _document(
            fetch(issuer.rstrip("/") + "/.well-known/openid-configuration"), "discovery"
        )
        if config.get("issuer") != issuer:
            raise OIDCError("OIDC discovery issuer mismatch")
        jwks_uri = config.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
            raise OIDCError("OIDC discovery requires an HTTPS jwks_uri")

        def refetch() -> dict[str, Any]:
            return _document(fetch(jwks_uri), "JWKS")

        return cls(refetch(), issuer=issuer, audience=audience, jwks_fetch=refetch, **kwargs)

    def __call__(self, token: str) -> dict[str, Any]:
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
        except ValueError as exc:
            raise OIDCError("malformed JWT") from exc
        header = _json_object(header_b64, "header")
        if "crit" in header or "b64" in header:
            raise OIDCError("unsupported JWT critical header")
        token_type = header.get("typ")
        if token_type is not None and (
            not isinstance(token_type, str)
            or token_type.lower().removeprefix("application/") not in _TOKEN_TYPES
        ):
            raise OIDCError("JWT type is not an access or ID token")
        alg = header.get("alg")
        if not isinstance(alg, str) or not alg:
            raise OIDCError("JWT algorithm must be a non-empty string")
        if alg not in self.algorithms:
            raise OIDCError(f"disallowed JWT algorithm: {alg}")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise OIDCError("JWT key id must be a non-empty string")
        jwk = self._key_set.get(kid)
        if jwk is None:
            raise OIDCError("no JWKS key matches the token 'kid'")
        _verify_signature(alg, jwk, f"{header_b64}.{payload_b64}".encode(), _b64url(sig_b64))
        claims = _json_object(payload_b64, "payload")
        validate_claims(self, claims)
        return claims
