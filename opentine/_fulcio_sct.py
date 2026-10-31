"""Offline check of the Signed Certificate Timestamps embedded in a Fulcio leaf.

Fulcio submits every precertificate to a Certificate Transparency log and
embeds the log's promise (RFC 6962 SCT, extension 1.3.6.1.4.1.11129.2.4.2) in
the final certificate. With ``--ct-key`` a keyless signature is accepted only
when at least one embedded SCT

* names a log whose id (SHA-256 of its DER SubjectPublicKeyInfo) matches a
  ``--ct-key`` key;
* verifies under that key over the RFC 6962 §3.2 ``digitally-signed`` struct
  for a ``precert_entry``: the leaf TBS with the SCT extension removed
  (``tbs_precertificate_bytes``) plus the SHA-256 of the issuer's key;
* carries a timestamp inside the certificate's validity window.
"""

from __future__ import annotations

import hashlib
import struct
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MAX_KEYS = 64

__all__ = ["ct_log_id", "load_ct_keys", "verify_scts"]


def ct_log_id(key) -> bytes:
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).digest()


def load_ct_keys(pem: bytes) -> list:
    """Every ``PUBLIC KEY`` block in *pem* (one file may hold several logs)."""
    marker, keys = b"-----END PUBLIC KEY-----", []
    for block in pem.split(marker)[:-1]:
        start = block.find(b"-----BEGIN PUBLIC KEY-----")
        if start < 0:
            raise ValueError("--ct-key is not PEM public keys")
        try:
            key = serialization.load_pem_public_key(block[start:] + marker)
        except ValueError as exc:
            raise ValueError(f"--ct-key is not a PEM public key: {exc}") from exc
        if not isinstance(key, ec.EllipticCurvePublicKey | rsa.RSAPublicKey):
            raise ValueError("--ct-key must be an ECDSA or RSA public key")
        keys.append(key)
    if not keys or len(keys) > _MAX_KEYS:
        raise ValueError(
            "--ct-key holds no PEM public key" if not keys else "too many --ct-key keys"
        )
    return keys


def _signed_data(sct, tbs: bytes, issuer_key_hash: bytes) -> bytes:
    millis = (sct.timestamp.replace(tzinfo=UTC) - _EPOCH) // timedelta(milliseconds=1)
    ext = sct.extension_bytes
    return (
        struct.pack(">BBQH", 0, 0, millis, 1)  # v1, certificate_timestamp, precert_entry
        + issuer_key_hash
        + len(tbs).to_bytes(3, "big")
        + tbs
        + struct.pack(">H", len(ext))
        + ext
    )


def _check_one(sct, keys: dict, tbs: bytes, issuer_hash: bytes, leaf) -> str | None:
    """``None`` when *sct* verifies, else the reason it does not."""
    key = keys.get(sct.log_id)
    if key is None:
        return "no embedded SCT is from a log in --ct-key"
    if sct.version != x509.certificate_transparency.Version.v1:
        return "embedded SCT has an unsupported version"
    if sct.entry_type != x509.certificate_transparency.LogEntryType.PRE_CERTIFICATE:
        return "embedded SCT is not for a precertificate"
    if not isinstance(sct.signature_hash_algorithm, hashes.SHA256):
        return "embedded SCT is not signed with SHA-256"
    data = _signed_data(sct, tbs, issuer_hash)
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sct.signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(sct.signature, data, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError):
        return "embedded SCT signature does not verify under its --ct-key log key"
    when = sct.timestamp.replace(tzinfo=UTC)
    if not leaf.not_valid_before_utc <= when <= leaf.not_valid_after_utc:
        return "embedded SCT timestamp is outside the certificate's validity"
    return None


def verify_scts(leaf: x509.Certificate, issuer: x509.Certificate, keys: list) -> None:
    """Raise ``ValueError`` unless one embedded SCT verifies under one of *keys*."""
    try:
        ext = leaf.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        )
        scts = list(ext.value)
    except x509.ExtensionNotFound:
        raise ValueError("certificate carries no embedded SCT, but --ct-key demands one") from None
    except ValueError as exc:
        raise ValueError(f"certificate SCT list is malformed: {exc}") from exc
    if not scts:
        raise ValueError("certificate carries no embedded SCT, but --ct-key demands one")
    by_id = {ct_log_id(key): key for key in keys}
    issuer_der = issuer.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    issuer_hash = hashlib.sha256(issuer_der).digest()
    tbs = leaf.tbs_precertificate_bytes
    reasons = [_check_one(sct, by_id, tbs, issuer_hash, leaf) for sct in scts]
    if None in reasons:
        return
    # Report the most specific failure: a known log's bad SCT beats an unknown log.
    unknown = "no embedded SCT is from a log in --ct-key"
    raise ValueError(next((r for r in reasons if r != unknown), unknown))
