"""Sigstore bundle v0.3 around a DSSE envelope, and its transparency-log receipt.

A plain ``tine export --format intoto`` line is a bare DSSE envelope. With
``--rekor`` (or ``--keyless``) the line is instead a Sigstore bundle -- the same
JSON other Sigstore tooling reads::

    {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
     "verificationMaterial": {"publicKey": {"hint": ...} | "certificate": {...},
                              "tlogEntries": [TransparencyLogEntry]},
     "dsseEnvelope": {payload, payloadType, signatures}}

``split`` accepts either shape, so a verifier reads both. ``check_entry`` is the
offline receipt check: SET, Merkle inclusion and checkpoint against a Rekor key
the caller supplies, and that the logged body is *this* envelope's entry.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from opentine._rekor_proof import (
    leaf_hash,
    log_id,
    verify_checkpoint,
    verify_inclusion,
    verify_set,
)

BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
_MEDIA_TYPES = frozenset(
    {
        BUNDLE_MEDIA_TYPE,
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "application/vnd.dev.sigstore.bundle+json;version=0.2",
    }
)

__all__ = ["BUNDLE_MEDIA_TYPE", "ReceiptResult", "check_entry", "make_bundle", "split"]


def make_bundle(envelope: dict, material: dict, entries: list[dict]) -> dict[str, Any]:
    return {
        "mediaType": BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {**material, "tlogEntries": entries},
        "dsseEnvelope": envelope,
    }


def split(document: Any) -> tuple[dict, dict, list]:
    """``(envelope, verificationMaterial, tlogEntries)`` from an envelope or a bundle."""
    if not isinstance(document, dict):
        raise ValueError("attestation line is not a JSON object")
    if "mediaType" not in document:
        return document, {}, []
    if document.get("mediaType") not in _MEDIA_TYPES:
        raise ValueError("unsupported Sigstore bundle mediaType")
    envelope, material = document.get("dsseEnvelope"), document.get("verificationMaterial")
    if not isinstance(envelope, dict) or not isinstance(material, dict):
        raise ValueError("bundle has no dsseEnvelope or verificationMaterial")
    entries = material.get("tlogEntries", [])
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise ValueError("bundle tlogEntries is malformed")
    return envelope, material, entries


@dataclass
class ReceiptResult:
    ok: bool
    status: str  # verified | invalid | absent | unchecked | no-key
    reason: str
    log_index: int | None = None
    integrated_time: int | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "log_index": self.log_index,
            "integrated_time": self.integrated_time,
            "reason": self.reason,
        }


def _b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("receipt field is not a base64 string")
    return base64.b64decode(value.encode("ascii"), validate=True)


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not str(value).isdigit():
        raise ValueError("receipt integer field is malformed")
    return int(value)


def _spki(pem_or_der: bytes) -> bytes:
    if pem_or_der.lstrip().startswith(b"-----BEGIN CERTIFICATE"):
        key = x509.load_pem_x509_certificate(pem_or_der).public_key()
    else:
        key = serialization.load_pem_public_key(pem_or_der)
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _check_body(body: bytes, envelope: dict, signer_spki: bytes) -> None:
    """The logged ``dsse`` 0.0.1 entry must be this envelope, signed by this key."""
    entry = json.loads(body.decode("utf-8"))
    spec = entry.get("spec") if isinstance(entry, dict) else None
    if entry.get("kind") != "dsse" or not isinstance(spec, dict):
        raise ValueError("logged entry is not a dsse entry")
    payload = base64.b64decode(str(envelope.get("payload", "")).encode("ascii"), validate=True)
    if (spec.get("payloadHash") or {}).get("value") != hashlib.sha256(payload).hexdigest():
        raise ValueError("logged entry is for a different payload")
    logged = spec.get("signatures")
    if not isinstance(logged, list) or not logged:
        raise ValueError("logged entry carries no signatures")
    sigs = {s.get("sig") for s in envelope.get("signatures") or [] if isinstance(s, dict)}
    for item in logged:
        if not isinstance(item, dict) or item.get("signature") not in sigs:
            raise ValueError("logged entry carries a signature this envelope does not")
        if _spki(_b64(item.get("verifier"))) != signer_spki:
            raise ValueError("logged entry names a different signing key")


def check_entry(entry: dict, envelope: dict, signer_key: Any, rekor_key: Any) -> ReceiptResult:
    """Verify one ``TransparencyLogEntry`` offline, fail-closed."""
    index = when = None
    try:
        index, when = _int(entry.get("logIndex")), _int(entry.get("integratedTime"))
        if _b64((entry.get("logId") or {}).get("keyId")) != log_id(rekor_key):
            raise ValueError("entry was logged by a different log than --rekor-key")
        body_b64 = entry.get("canonicalizedBody")
        body = _b64(body_b64)
        promise = (entry.get("inclusionPromise") or {}).get("signedEntryTimestamp")
        verify_set(rekor_key, body_b64, when, index, _b64(promise))
        proof = entry.get("inclusionProof")
        if not isinstance(proof, dict):
            raise ValueError("entry carries no inclusion proof")
        size, root = _int(proof.get("treeSize")), _b64(proof.get("rootHash"))
        hashes = proof.get("hashes")
        if not isinstance(hashes, list):
            raise ValueError("inclusion proof has no hashes")
        path = [_b64(h) for h in hashes]
        verify_inclusion(_int(proof.get("logIndex")), size, leaf_hash(body), path, root)
        note = (proof.get("checkpoint") or {}).get("envelope")
        verify_checkpoint(rekor_key, note, size, root)
        spki = signer_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        _check_body(body, envelope, spki)
    except (AttributeError, ValueError, binascii.Error, UnicodeDecodeError) as exc:
        return ReceiptResult(False, "invalid", str(exc), index, when)
    return ReceiptResult(True, "verified", "ok", index, when)
