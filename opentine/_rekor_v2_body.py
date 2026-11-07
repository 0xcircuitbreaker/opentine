"""The ``dsse`` v0.0.2 entry body a Rekor v2 log stores, checked against an envelope.

The body is JSON ``{"apiVersion": "0.0.2", "kind": "dsse", "spec": {"dsseV002":
{"payloadHash": {"algorithm": "SHA2_256", "digest": <b64>}, "signatures":
[{"content": <b64 signature>, "verifier": {"publicKey": {"rawBytes": <b64 SPKI>}
| "x509Certificate": {"rawBytes": <b64 DER>}, "keyDetails": ...}}]}}}`` (the
rekor-tiles ``DSSELogEntryV002`` message in protobuf JSON form). Every logged
signature must be one of the envelope's and name the signing key.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from opentine._rekor_v2 import _der, is_v2, verify_entry
from opentine.sigstore_bundle import ReceiptResult


def _b64(value: Any) -> bytes:
    return base64.b64decode(str(value).encode("ascii"), validate=True)


def _verifier_spki(verifier: Any) -> bytes:
    if not isinstance(verifier, dict):
        raise ValueError("logged signature has no verifier")
    if "x509Certificate" in verifier:
        cert = x509.load_der_x509_certificate(_b64(verifier["x509Certificate"]["rawBytes"]))
        return _der(cert.public_key())
    key = serialization.load_der_public_key(_b64(verifier["publicKey"]["rawBytes"]))
    return _der(key)


def check_body(body: bytes, envelope: dict, signer_spki: bytes) -> None:
    entry = json.loads(body.decode("utf-8"))
    spec = ((entry.get("spec") or {}).get("dsseV002")) if isinstance(entry, dict) else None
    if entry.get("kind") != "dsse" or entry.get("apiVersion") != "0.0.2" or not spec:
        raise ValueError("logged entry is not a dsse v0.0.2 entry")
    payload = _b64(envelope.get("payload", ""))
    digest = spec.get("payloadHash") or {}
    if digest.get("algorithm") != "SHA2_256" or _b64(digest.get("digest")) != (
        hashlib.sha256(payload).digest()
    ):
        raise ValueError("logged entry is for a different payload")
    sigs = {s.get("sig") for s in envelope.get("signatures") or [] if isinstance(s, dict)}
    logged = spec.get("signatures")
    if not isinstance(logged, list) or not logged:
        raise ValueError("logged entry carries no signatures")
    for item in logged:
        if not isinstance(item, dict) or item.get("content") not in sigs:
            raise ValueError("logged entry carries a signature this envelope does not")
        if _verifier_spki(item.get("verifier")) != signer_spki:
            raise ValueError("logged entry names a different signing key")


def check_v2_entry(logs: list, entry: dict, envelope: dict, signer_key: Any) -> ReceiptResult:
    """A v2 ``TransparencyLogEntry`` under the trusted root's tile logs, fail-closed."""
    index = None
    try:
        if not is_v2(entry):
            raise ValueError("entry is not a Rekor v2 (0.0.2) entry")
        index, body = verify_entry(entry, logs)
        check_body(body, envelope, _der(signer_key))
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        return ReceiptResult(False, "invalid", str(exc), index, None)
    # Proof, checkpoint and body hold; but keyless needs a verified signing time, which
    # for a v2 log comes from an RFC 3161 token in the bundle -- not checked yet.
    reason = f"Rekor v2 receipt {index} verified; keyless signing time needs a TSA token"
    return ReceiptResult(False, "unchecked", reason, index, None)
