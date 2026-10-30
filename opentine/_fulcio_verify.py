"""Offline verification of a keyless (Fulcio-certificate) DSSE envelope.

A keyless envelope is trusted only when all of these hold:

* the DSSE signature verifies under the certificate's ECDSA key;
* the certificate chains, signature by signature, to a certificate in the
  caller's ``--fulcio-root`` file (Fulcio root and intermediates, PEM), and
  every certificate on that path is valid at the log's ``integratedTime``;
* the leaf is a code-signing certificate whose SAN equals ``--cert-identity``
  and whose OIDC-issuer extension (1.3.6.1.4.1.57264.1.8, or the legacy .1.1)
  equals ``--cert-oidc-issuer``.

``integratedTime`` comes from a receipt the caller has already verified: a
short-lived certificate proves nothing without a trusted signing time.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from opentine.intoto import PAYLOAD_TYPE, pae

ISSUER_V2 = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.8")
ISSUER_V1 = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
_MAX_DEPTH = 4

__all__ = ["cert_identity", "leaf_from_material", "load_roots", "verify_keyless"]


def load_roots(pem: bytes) -> list[x509.Certificate]:
    try:
        roots = x509.load_pem_x509_certificates(pem)
    except ValueError as exc:
        raise ValueError(f"--fulcio-root is not PEM certificates: {exc}") from exc
    return roots


def leaf_from_material(material: dict) -> x509.Certificate | None:
    """The signing certificate in bundle ``verificationMaterial``, if it has one."""
    if "certificate" in material:
        raw = (material.get("certificate") or {}).get("rawBytes")
    elif "x509CertificateChain" in material:
        raw = ((material.get("x509CertificateChain") or {}).get("certificates") or [{}])[0]
        raw = raw.get("rawBytes") if isinstance(raw, dict) else None
    else:
        return None
    try:
        return x509.load_der_x509_certificate(base64.b64decode(str(raw), validate=True))
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"bundle certificate is malformed: {exc}") from exc


def _der_utf8(raw: bytes) -> str:
    if len(raw) < 2 or raw[0] != 0x0C or raw[1] & 0x80 and raw[1] != 0x81:
        raise ValueError("issuer extension is not a short DER UTF8String")
    start = 2 if raw[1] < 0x80 else 3
    return raw[start:].decode("utf-8")


def cert_identity(cert: x509.Certificate) -> tuple[list[str], str | None]:
    """``(SAN values, OIDC issuer)`` as Fulcio wrote them into *cert*."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(v) for v in san.get_values_for_type(x509.RFC822Name)]
        names += [str(v) for v in san.get_values_for_type(x509.UniformResourceIdentifier)]
    except x509.ExtensionNotFound:
        names = []
    issuer = None
    for oid, decode in ((ISSUER_V2, _der_utf8), (ISSUER_V1, bytes.decode)):
        try:
            issuer = decode(cert.extensions.get_extension_for_oid(oid).value.value)
            break
        except x509.ExtensionNotFound:
            continue
    return names, issuer


def _valid_at(cert: x509.Certificate, when: datetime) -> bool:
    return cert.not_valid_before_utc <= when <= cert.not_valid_after_utc


def _chain_to_root(leaf: x509.Certificate, roots: list[x509.Certificate], when: datetime) -> None:
    cert = leaf
    for _ in range(_MAX_DEPTH):
        if not _valid_at(cert, when):
            raise ValueError("a certificate on the chain was not valid at the signing time")
        if cert in roots and cert.issuer == cert.subject:
            return
        for candidate in roots:
            if candidate.subject != cert.issuer:
                continue
            try:
                cert.verify_directly_issued_by(candidate)
            except (InvalidSignature, ValueError, TypeError):
                continue
            cert = candidate
            break
        else:
            raise ValueError("certificate does not chain to a trusted --fulcio-root")
    raise ValueError("certificate chain is too long")


def verify_keyless(
    envelope: dict,
    leaf: x509.Certificate,
    *,
    roots: list[x509.Certificate],
    identity: str,
    issuer: str,
    integrated_time: int,
) -> None:
    """Raise ``ValueError`` with the reason unless every keyless check passes."""
    key = leaf.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("keyless certificate key is not ECDSA")
    try:
        body = base64.b64decode(str(envelope.get("payload", "")), validate=True)
        sigs = [base64.b64decode(str(s.get("sig")), validate=True) for s in envelope["signatures"]]
    except (AttributeError, KeyError, TypeError, binascii.Error) as exc:
        raise ValueError(f"envelope is malformed: {exc}") from exc
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise ValueError(f"payloadType must be {PAYLOAD_TYPE}")
    for sig in sigs:
        try:
            key.verify(sig, pae(PAYLOAD_TYPE, body), ec.ECDSA(hashes.SHA256()))
            break
        except InvalidSignature:
            continue
    else:
        raise ValueError("no signature verifies under the certificate key")
    try:
        usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usage = []
    if ExtendedKeyUsageOID.CODE_SIGNING not in usage:
        raise ValueError("certificate is not a code-signing certificate")
    when = datetime.fromtimestamp(integrated_time, tz=UTC)
    _chain_to_root(leaf, roots, when)
    names, cert_issuer = cert_identity(leaf)
    if identity not in names:
        raise ValueError("certificate identity does not match --cert-identity")
    if cert_issuer != issuer:
        raise ValueError("certificate OIDC issuer does not match --cert-oidc-issuer")
