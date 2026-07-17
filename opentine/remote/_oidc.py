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


class OIDCError(PermissionError):
    pass


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
        value = json.loads(_b64url(segment))
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
        raise OIDCError(f"malformed JWT {label}") from exc
    if not isinstance(value, dict):
        raise OIDCError(f"JWT {label} must be an object")
    return value


def _document(raw: bytes | str, label: str) -> dict[str, Any]:
    if not isinstance(raw, (bytes, str)) or len(raw) > 4 * 1024 * 1024:
        raise OIDCError(f"OIDC {label} exceeds the document limit")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
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
    ):
        keys = jwks.get("keys", []) if isinstance(jwks, dict) else jwks
        if not isinstance(keys, list) or not keys or len(keys) > 100:
            raise OIDCError("JWKS must contain between 1 and 100 keys")
        self.keys: dict[str, dict[str, Any]] = {}
        for key in keys:
            kid = key.get("kid") if isinstance(key, dict) else None
            if not isinstance(kid, str) or not kid or kid in self.keys:
                raise OIDCError("JWKS key ids must be unique non-empty strings")
            self.keys[kid] = key
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
        jwks = _document(fetch(jwks_uri), "JWKS")
        return cls(jwks, issuer=issuer, audience=audience, **kwargs)

    def __call__(self, token: str) -> dict[str, Any]:
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
        except ValueError as exc:
            raise OIDCError("malformed JWT") from exc
        header = _json_object(header_b64, "header")
        if "crit" in header or "b64" in header:
            raise OIDCError("unsupported JWT critical header")
        alg = header.get("alg")
        if alg not in self.algorithms:
            raise OIDCError(f"disallowed JWT algorithm: {alg}")
        jwk = self.keys.get(header.get("kid"))
        if jwk is None:
            raise OIDCError("no JWKS key matches the token 'kid'")
        _verify_signature(alg, jwk, f"{header_b64}.{payload_b64}".encode(), _b64url(sig_b64))
        claims = _json_object(payload_b64, "payload")
        self._validate(claims)
        return claims

    def _validate(self, claims: dict[str, Any]) -> None:
        if claims.get("iss") != self.issuer:
            raise OIDCError("JWT issuer mismatch")
        audience = claims.get("aud")
        allowed = audience if isinstance(audience, list) else [audience]
        if not all(isinstance(item, str) for item in allowed):
            raise OIDCError("JWT audience must be a string or list of strings")
        if self.audience not in allowed:
            raise OIDCError("JWT audience mismatch")
        authorized_party = claims.get("azp")
        if (len(allowed) > 1 or authorized_party is not None) and authorized_party != self.audience:
            raise OIDCError("JWT authorized party mismatch")
        now = self.now()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            raise OIDCError("JWT verifier clock is invalid")
        expiry = claims.get("exp")
        if (
            isinstance(expiry, bool)
            or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry)
            or now >= expiry + self.leeway
        ):
            raise OIDCError("JWT is expired or missing 'exp'")
        not_before = claims.get("nbf")
        if not_before is not None:
            if (
                isinstance(not_before, bool)
                or not isinstance(not_before, (int, float))
                or not math.isfinite(not_before)
                or now < not_before - self.leeway
            ):
                raise OIDCError("JWT is not yet valid")
