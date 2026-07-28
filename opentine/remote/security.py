"""Development tokens, OIDC integration, RBAC, and encryption providers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from collections.abc import Callable
from typing import Any

from opentine.remote.interfaces import Identity


class AuthenticationError(PermissionError):
    pass


class StaticTokenIdentityProvider:
    def __init__(self, tokens: dict[str, Identity]):
        if any(not isinstance(token, str) or not token for token in tokens):
            raise ValueError("static bearer tokens must be non-empty strings")
        self._tokens = {
            hashlib.sha256(token.encode()).digest(): identity for token, identity in tokens.items()
        }

    def authenticate(self, headers: dict[str, str]) -> Identity:
        authorization = headers.get("authorization", "")
        if not authorization.lower().startswith("bearer "):
            raise AuthenticationError("missing bearer token")
        presented = hashlib.sha256(authorization[7:].strip().encode()).digest()
        for digest, identity in self._tokens.items():
            if hmac.compare_digest(presented, digest):
                return identity
        raise AuthenticationError("invalid bearer token")


class OIDCIdentityProvider:
    """OIDC identity provider. The ``verifier`` must validate issuer, audience, expiry, and
    signature; ``from_jwks`` wires the built-in standards-correct ``JWTVerifier``."""

    def __init__(
        self,
        verifier: Callable[[str], dict[str, Any]],
        *,
        tenant_claim: str = "tenant",
        roles_claim: str = "roles",
        default_roles: tuple[str, ...] = (),
    ):
        self.verifier = verifier
        self.tenant_claim = tenant_claim
        self.roles_claim = roles_claim
        #: Roles granted when the token carries no roles claim at all. Empty by
        #: default so a misconfigured issuer — or one that simply stopped emitting
        #: the claim — grants nothing instead of silently conferring read access to
        #: every run in the tenant. Set it explicitly to opt into a standing role.
        self.default_roles = tuple(default_roles)

    @classmethod
    def from_jwks(
        cls, jwks: dict[str, Any], *, issuer: str, audience: str, **kwargs: Any
    ) -> OIDCIdentityProvider:
        from opentine.remote._oidc import JWTVerifier

        claims = {
            key: kwargs.pop(key)
            for key in ("tenant_claim", "roles_claim", "default_roles")
            if key in kwargs
        }
        verifier = JWTVerifier(jwks, issuer=issuer, audience=audience, **kwargs)
        return cls(verifier, **claims)

    @classmethod
    def from_discovery(
        cls,
        *,
        issuer: str,
        audience: str,
        fetch: Callable[[str], bytes],
        **kwargs: Any,
    ) -> OIDCIdentityProvider:
        from opentine.remote._oidc import JWTVerifier

        claims = {
            key: kwargs.pop(key)
            for key in ("tenant_claim", "roles_claim", "default_roles")
            if key in kwargs
        }
        verifier = JWTVerifier.from_discovery(issuer, audience, fetch, **kwargs)
        return cls(verifier, **claims)

    def authenticate(self, headers: dict[str, str]) -> Identity:
        authorization = headers.get("authorization", "")
        if not authorization.lower().startswith("bearer "):
            raise AuthenticationError("missing bearer token")
        claims = self.verifier(authorization[7:].strip())
        subject = claims.get("sub")
        tenant = claims.get(self.tenant_claim)
        if not isinstance(subject, str) or not subject or not isinstance(tenant, str) or not tenant:
            raise AuthenticationError("OIDC token lacks subject or tenant")
        roles = claims[self.roles_claim] if self.roles_claim in claims else self.default_roles
        if isinstance(roles, str):
            roles = roles.split()
        if not isinstance(roles, (list, tuple)) or not all(isinstance(role, str) for role in roles):
            raise AuthenticationError("OIDC roles claim must be a string or list of strings")
        try:
            return Identity(subject, tenant, tuple(dict.fromkeys(roles)), claims)
        except ValueError as exc:
            raise AuthenticationError("OIDC identity contains invalid text") from exc


class RoleAuthorizationPolicy:
    _actions = {
        "reader": {"capabilities", "fetch", "negotiate", "read_ref", "search"},
        "writer": {
            "capabilities",
            "fetch",
            "negotiate",
            "read_ref",
            "search",
            "upload",
            "update_ref",
        },
        "admin": {"*"},
    }

    def authorize(self, identity: Identity, action: str, tenant: str) -> bool:
        if identity.tenant != tenant:
            return False
        allowed = set().union(*(self._actions.get(role, set()) for role in identity.roles))
        return "*" in allowed or action in allowed


class LocalKeyProvider:
    """AES-GCM envelope used for development and as the KMS adapter contract."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        self.key = key

    @classmethod
    def from_env(cls, name: str = "TINE_KMS_KEY") -> LocalKeyProvider:
        raw = os.environ.get(name)
        if not raw:
            raise RuntimeError(f"{name} is required for encrypted remote storage")
        try:
            return cls(base64.b64decode(raw, validate=True))
        except ValueError as exc:
            raise ValueError(f"{name} must be a base64 AES key") from exc

    def encrypt(self, tenant: str, plaintext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)
        key = hmac.new(
            self.key, b"opentine.tenant-key.v1\0" + tenant.encode(), hashlib.sha256
        ).digest()
        return b"TINEAES2" + nonce + AESGCM(key).encrypt(nonce, plaintext, tenant.encode())

    def derive_audit_key(self) -> bytes:
        return hmac.new(self.key, b"opentine.audit-chain-key.v1\0", hashlib.sha256).digest()

    def decrypt(self, tenant: str, ciphertext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if not ciphertext.startswith((b"TINEAES1", b"TINEAES2")):
            raise ValueError("invalid encrypted object header")
        nonce, body = ciphertext[8:20], ciphertext[20:]
        key = self.key
        if ciphertext.startswith(b"TINEAES2"):
            key = hmac.new(
                self.key, b"opentine.tenant-key.v1\0" + tenant.encode(), hashlib.sha256
            ).digest()
        return AESGCM(key).decrypt(nonce, body, tenant.encode())


class KMSKeyProvider:
    """Adapter for KMS encrypt/decrypt and audit-key derivation callables."""

    def __init__(
        self,
        encrypt: Callable[[str, bytes], bytes],
        decrypt: Callable[[str, bytes], bytes],
        derive_audit_key: Callable[[], bytes] | None = None,
    ):
        self._encrypt = encrypt
        self._decrypt = decrypt
        self._derive_audit_key = derive_audit_key

    def encrypt(self, tenant: str, plaintext: bytes) -> bytes:
        return self._encrypt(tenant, plaintext)

    def decrypt(self, tenant: str, ciphertext: bytes) -> bytes:
        return self._decrypt(tenant, ciphertext)

    def derive_audit_key(self) -> bytes:
        if self._derive_audit_key is None:
            raise RuntimeError("KMS audit-key derivation is not configured")
        key = self._derive_audit_key()
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("derived audit HMAC key must contain at least 16 bytes")
        return key
