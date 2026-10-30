"""Offline stand-ins for Rekor, Fulcio and GitHub's OIDC endpoint.

A real RFC 6962 Merkle tree over a few leaves, a local ECDSA P-256 log key that
signs SETs and checkpoints, and a local Fulcio CA (root -> intermediate -> leaf
with SAN, code-signing EKU and the 1.3.6.1.4.1.57264.1.8 issuer extension). The
handler is mounted as an ``httpx.MockTransport``; nothing reaches a network.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ISSUER_URL = "https://token.actions.example"
IDENTITY = "ci-bot@example.com"


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return _h(b"\x01" + _root(leaves[:k]) + _root(leaves[k:]))


def _path(index: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) <= 1:
        return []
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    if index < k:
        return _path(index, leaves[:k]) + [_root(leaves[k:])]
    return _path(index - k, leaves[k:]) + [_root(leaves[:k])]


def _spki(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def fake_jwt(claims: dict[str, Any]) -> str:
    def seg(obj: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.c2lnbmF0dXJlLXNlY3JldA"


class FakeLog:
    """An in-memory Rekor: accepts dsse entries and returns real receipts."""

    def __init__(self, filler: int = 4) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.log_id = _h(_spki(self.key.public_key()))
        self.leaves = [_h(b"\x00" + b"filler-%d" % i) for i in range(filler)]
        self.time_offset = 0
        self.posted: list[Any] = []

    def public_pem(self) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def _sign(self, data: bytes) -> bytes:
        return self.key.sign(data, ec.ECDSA(hashes.SHA256()))

    def accept(self, proposed: dict) -> dict:
        self.posted.append(proposed)
        content = proposed["spec"]["proposedContent"]
        envelope = json.loads(content["envelope"])
        verifier = content["verifiers"][0]
        payload = base64.b64decode(envelope["payload"])
        body = {
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "envelopeHash": {
                    "algorithm": "sha256",
                    "value": _h(content["envelope"].encode()).hex(),
                },
                "payloadHash": {"algorithm": "sha256", "value": _h(payload).hex()},
                "signatures": [
                    {"signature": s["sig"], "verifier": verifier} for s in envelope["signatures"]
                ],
            },
        }
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        body_b64 = base64.b64encode(raw).decode()
        index = len(self.leaves)
        self.leaves += [_h(b"\x00" + raw), _h(b"\x00trailing")]
        size, root = len(self.leaves), _root(self.leaves)
        when = int(dt.datetime.now(dt.UTC).timestamp()) + self.time_offset
        set_payload = json.dumps(
            {
                "body": body_b64,
                "integratedTime": when,
                "logID": self.log_id.hex(),
                "logIndex": index,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        note = f"rekor.test - 42\n{size}\n{base64.b64encode(root).decode()}\n"
        sig = base64.b64encode(self.log_id[:4] + self._sign(note.encode())).decode()
        return {
            "24296fb24b8ad77a" + "0" * 48: {
                "body": body_b64,
                "integratedTime": when,
                "logID": self.log_id.hex(),
                "logIndex": index,
                "verification": {
                    "signedEntryTimestamp": base64.b64encode(self._sign(set_payload)).decode(),
                    "inclusionProof": {
                        "logIndex": index,
                        "treeSize": size,
                        "rootHash": root.hex(),
                        "hashes": [h.hex() for h in _path(index, self.leaves)],
                        "checkpoint": note + "\n— rekor.test " + sig + "\n",
                    },
                },
            }
        }


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class FakeFulcio:
    """A local root -> intermediate CA issuing Fulcio-shaped leaf certificates."""

    def __init__(self, identity: str = IDENTITY, issuer: str = ISSUER_URL) -> None:
        self.identity, self.issuer = identity, issuer
        now = dt.datetime.now(dt.UTC)
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = self._cert(
            _name("fake-root"),
            _name("fake-root"),
            self.root_key.public_key(),
            self.root_key,
            now - dt.timedelta(days=1),
            now + dt.timedelta(days=30),
            ca=True,
        )
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        self.inter = self._cert(
            _name("fake-inter"),
            _name("fake-root"),
            self.inter_key.public_key(),
            self.root_key,
            now - dt.timedelta(days=1),
            now + dt.timedelta(days=30),
            ca=True,
        )
        self.seen_tokens: list[str] = []

    @staticmethod
    def _cert(subject, issuer, public, signer, start, end, *, ca=False, extra=()):
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        )
        for ext in extra:
            builder = builder.add_extension(ext, critical=False)
        return builder.sign(signer, hashes.SHA256())

    def roots_pem(self) -> bytes:
        return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (self.inter, self.root))

    def issue(self, public) -> x509.Certificate:
        now = dt.datetime.now(dt.UTC)
        issuer_der = b"\x0c" + bytes([len(self.issuer)]) + self.issuer.encode()
        extra = (
            x509.SubjectAlternativeName([x509.RFC822Name(self.identity)]),
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.8"), issuer_der),
        )
        return self._cert(
            x509.Name([]),
            _name("fake-inter"),
            public,
            self.inter_key,
            now - dt.timedelta(minutes=1),
            now + dt.timedelta(minutes=10),
            extra=extra,
        )

    def accept(self, request: dict) -> dict:
        token = request["credentials"]["oidcIdentityToken"]
        self.seen_tokens.append(token)
        content = request["publicKeyRequest"]["publicKey"]["content"].encode()
        public = serialization.load_pem_public_key(content)
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        proof = base64.b64decode(request["publicKeyRequest"]["proofOfPossession"])
        public.verify(
            proof, (claims.get("email") or claims["sub"]).encode(), ec.ECDSA(hashes.SHA256())
        )
        chain = [self.issue(public), self.inter, self.root]
        pems = [c.public_bytes(serialization.Encoding.PEM).decode() for c in chain]
        return {"signedCertificateEmbeddedSct": {"chain": {"certificates": pems}}}


def transport(log: FakeLog, fulcio: FakeFulcio | None = None, gh_token: str | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/log/entries":
            return httpx.Response(201, json=log.accept(json.loads(request.content)))
        if request.url.path == "/api/v2/signingCert" and fulcio is not None:
            return httpx.Response(201, json=fulcio.accept(json.loads(request.content)))
        if request.url.path == "/gh-token" and gh_token is not None:
            assert request.url.params.get("audience") == "sigstore"
            return httpx.Response(200, json={"value": gh_token})
        return httpx.Response(404, json={"message": "not found"})

    return httpx.MockTransport(handler)
