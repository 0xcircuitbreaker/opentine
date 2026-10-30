"""Sigstore keyless signing: an OIDC identity becomes a short-lived Fulcio cert.

Signing (``tine export --format intoto --keyless``): find an OIDC identity token
(``--identity-token``, ``SIGSTORE_ID_TOKEN``, or GitHub Actions' ambient token
for audience ``sigstore``), generate an ephemeral ECDSA P-256 key, prove
possession by signing the token's identity claim, and ask Fulcio v2 for a
certificate binding that key to the identity. The key signs the DSSE envelope
and is then dropped. The token is never logged, printed or written: it travels
only in the request body, and every error is scrubbed of it.

Verification lives in :mod:`opentine._fulcio_verify`.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from opentine.intoto import PAYLOAD_TYPE, pae
from opentine.kernel import canonical_json
from opentine.rekor import SigstoreHTTPError, post_json, request_json

DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
_SIGSTORE_AUDIENCE = "sigstore"

__all__ = [
    "DEFAULT_FULCIO_URL",
    "KeylessSigner",
    "ambient_token",
    "identity_claim",
    "request_certificate",
]


def ambient_token() -> str | None:
    """GitHub Actions' OIDC token for audience ``sigstore``, when the job may mint one."""
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        return None
    joiner = "&" if "?" in url else "?"
    reply = request_json(
        "GET",
        f"{url}{joiner}audience={_SIGSTORE_AUDIENCE}",
        headers={"Authorization": f"bearer {bearer}"},
        secrets=(bearer,),
    )
    token = reply.get("value") if isinstance(reply, dict) else None
    if not isinstance(token, str) or not token:
        raise SigstoreHTTPError("GitHub Actions returned no identity token")
    return token


def identity_claim(token: str) -> str:
    """The claim Fulcio's proof of possession covers: ``email`` if present, else ``sub``."""
    try:
        segment = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (IndexError, ValueError, binascii.Error, UnicodeDecodeError):
        raise ValueError("identity token is not a JWT") from None
    claim = claims.get("email") or claims.get("sub") if isinstance(claims, dict) else None
    if not isinstance(claim, str) or not claim:
        raise ValueError("identity token has no email or sub claim")
    return claim


def request_certificate(token: str, key: ec.EllipticCurvePrivateKey, url: str) -> list[bytes]:
    """Fulcio v2 ``signingCert``: the PEM chain (leaf first) for *key*'s public half."""
    proof = key.sign(identity_claim(token).encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    body = {
        "credentials": {"oidcIdentityToken": token},
        "publicKeyRequest": {
            "publicKey": {"algorithm": "ECDSA", "content": pem.decode("ascii")},
            "proofOfPossession": base64.b64encode(proof).decode("ascii"),
        },
    }
    reply = post_json(url.rstrip("/") + "/api/v2/signingCert", body, secrets=(token,))
    try:
        signed = reply.get("signedCertificateEmbeddedSct") or reply["signedCertificateDetachedSct"]
        chain = [c.encode("ascii") for c in signed["chain"]["certificates"]]
        x509.load_pem_x509_certificate(chain[0])
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        raise SigstoreHTTPError("Fulcio reply carries no certificate chain") from None
    return chain


class KeylessSigner:
    """An ephemeral P-256 key and the Fulcio certificate that names its owner."""

    def __init__(self, token: str, fulcio_url: str = DEFAULT_FULCIO_URL) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        chain = request_certificate(token, self._key, fulcio_url)
        self.leaf_pem = chain[0]
        leaf = x509.load_pem_x509_certificate(self.leaf_pem)
        ours = self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        theirs = leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if ours != theirs:
            raise SigstoreHTTPError("Fulcio certified a different key than the one requested")
        self.leaf_der = leaf.public_bytes(serialization.Encoding.DER)

    def sign(self, statement: dict[str, Any]) -> dict[str, Any]:
        body = canonical_json(statement)
        sig = self._key.sign(pae(PAYLOAD_TYPE, body), ec.ECDSA(hashes.SHA256()))
        return {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(body).decode("ascii"),
            "signatures": [{"sig": base64.b64encode(sig).decode("ascii")}],
        }

    def material(self) -> dict[str, Any]:
        return {"certificate": {"rawBytes": base64.b64encode(self.leaf_der).decode("ascii")}}
