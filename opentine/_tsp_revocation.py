"""Revocation data embedded in an RFC 3161 token (0.50): CRLs and OCSP responses.

A TSA (or whoever archives a token) may put CRLs, and RFC 5940 OCSP responses,
in ``SignedData.crls``. That field lies outside the TSA's signature, so it can
be stripped without trace: embedded revocation data can only *fail* a token,
never strengthen it, and its absence is not a finding. What is checked, offline:

* each CRL or OCSP response must parse and be signed by a certificate on the
  token's path (the CA that issued the checked certificate, or for OCSP that CA
  or a responder it issued with the ``id-kp-OCSPSigning`` EKU), else
  ``timestamp.revocation-invalid``;
* a certificate on the path that it lists as revoked at or before ``genTime``,
  or revoked for ``keyCompromise``/``cACompromise`` at any time, fails the token
  with ``timestamp.revoked``.

Freshness (``thisUpdate``/``nextUpdate``) is not judged: a stale "good" answer
cannot pass anything, and a "revoked" answer stays true once issued.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

_BROKEN = (ValueError, TypeError, UnsupportedAlgorithm, x509.InvalidVersion)
_COMPROMISE = (x509.ReasonFlags.key_compromise, x509.ReasonFlags.ca_compromise)


def _verify(key: object, signature: bytes, data: bytes, algorithm) -> bool:
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, padding.PKCS1v15(), algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(algorithm))
        elif isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            key.verify(signature, data)
        else:
            return False
    except (InvalidSignature, TypeError, ValueError, UnsupportedAlgorithm):
        return False
    return True


def _compromised(reason: object) -> bool:
    return reason in _COMPROMISE


def _crl_problem(der: bytes, path: list[x509.Certificate], when: datetime):
    try:
        crl = x509.load_der_x509_crl(der)
    except ValueError:
        return "timestamp.revocation-invalid", "an embedded CRL does not parse"
    issuer = next((c for c in path if c.subject == crl.issuer), None)
    if issuer is None or not crl.is_signature_valid(issuer.public_key()):
        detail = "an embedded CRL is not signed by a CA on the TSA's path"
        return "timestamp.revocation-invalid", detail
    for cert in path:
        if cert.issuer != crl.issuer:
            continue
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if entry is None:
            continue
        try:
            reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
        except x509.ExtensionNotFound:
            reason = None
        if entry.revocation_date_utc <= when or _compromised(reason):
            name = cert.subject.rfc4514_string()
            return "timestamp.revoked", f"embedded CRL revokes {name} before genTime"
    return None


def _responder(resp, path: list[x509.Certificate]) -> x509.Certificate | None:
    for cert in [*resp.certificates, *path]:
        matches = (
            resp.responder_name == cert.subject
            if resp.responder_name is not None
            else resp.responder_key_hash == _key_hash(cert)
        )
        if not matches:
            continue
        if cert in path:
            return cert
        issuer = next((c for c in path if c.subject == cert.issuer), None)
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            cert.verify_directly_issued_by(issuer) if issuer else None
        except (x509.ExtensionNotFound, InvalidSignature, ValueError, TypeError):
            continue
        if issuer is not None and ExtendedKeyUsageOID.OCSP_SIGNING in eku:
            return cert
    return None


def _key_hash(cert: x509.Certificate) -> bytes:
    return x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest


def _names(single, issuer: x509.Certificate | None) -> bool:
    """The single response's CertID names *issuer* (its name hash)."""
    if issuer is None:
        return False
    name = hashlib.new(single.hash_algorithm.name, issuer.subject.public_bytes()).digest()
    return hmac.compare_digest(name, single.issuer_name_hash)


def _ocsp_problem(der: bytes, path: list[x509.Certificate], when: datetime):
    try:
        resp = ocsp.load_der_ocsp_response(der)
        ok = resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        singles = list(resp.responses) if ok else []
        signer = _responder(resp, path) if ok else None
        valid = signer is not None and _verify(
            signer.public_key(), resp.signature, resp.tbs_response_bytes,
            resp.signature_hash_algorithm,
        )  # fmt: skip
    except (ValueError, TypeError, UnsupportedAlgorithm):
        valid, singles = False, []
    if not valid:
        detail = "an embedded OCSP response is not signed by the TSA's CA or its responder"
        return "timestamp.revocation-invalid", detail
    for single in singles:
        if single.certificate_status != ocsp.OCSPCertStatus.REVOKED:
            continue
        for cert in path:
            issuer = next((c for c in path if c.subject == cert.issuer), None)
            if cert.serial_number != single.serial_number or not _names(single, issuer):
                continue
            if single.revocation_time_utc <= when or _compromised(single.revocation_reason):
                name = cert.subject.rfc4514_string()
                return "timestamp.revoked", f"embedded OCSP response revokes {name} before genTime"
    return None


def revocation_problem(
    crls: list[bytes], responses: list[bytes], path: list[x509.Certificate], when: datetime
) -> tuple[str, str] | None:
    """``(reason, detail)`` when embedded revocation data fails the token at *when*."""
    checks = [(_crl_problem, der, "CRL") for der in crls]
    checks += [(_ocsp_problem, der, "OCSP response") for der in responses]
    for check, der, kind in checks:
        try:  # cryptography parses lazily: a flaw can surface on any accessor
            found = check(der, path, when)
        except _BROKEN:
            found = "timestamp.revocation-invalid", f"an embedded {kind} is malformed"
        if found:
            return found
    return None


__all__ = ["revocation_problem"]
