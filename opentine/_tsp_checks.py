"""RFC 3161 / RFC 5816 checks :func:`opentine._tsp_verify.verify_token` adds in 0.41 (X26).

* **Signing-certificate binding** (RFC 3161 §2.4.1, RFC 5816): the signed
  attributes carry exactly one ESS ``signingCertificate`` (SHA-1 ESSCertID) or
  ``signingCertificateV2`` (ESSCertIDv2, any listed hash, default SHA-256), and
  its first ``certHash`` is the hash of the certificate that verified the
  signature; an ``issuerSerial`` present must name that certificate's serial.
  Without it a TSA's signature could be re-attributed to another certificate
  for the same key.
* **Critical extensions**: a TSTInfo extension marked critical, or an
  unrecognised critical extension in any certificate on the path, is refused
  (no TSTInfo extension is understood here).
* **Extended key usage** (§2.3): the TSA certificate's EKU is present, marked
  critical, and holds only ``id-kp-timeStamping``.
* **CA key usage**: an issuing certificate with a KeyUsage extension must
  assert ``keyCertSign``.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from opentine import _der
from opentine._der import OCTETS, SEQUENCE
from opentine._tsp import HASHES, Token

ESS_V1 = "1.2.840.113549.1.9.16.2.12"
ESS_V2 = "1.2.840.113549.1.9.16.2.47"


def _ess_ids(token: Token) -> tuple[str, list[_der.Node]] | None:
    v1, v2 = token.attrs.get(ESS_V1) or [], token.attrs.get(ESS_V2) or []
    if len(v1) + len(v2) != 1:
        return None
    version, value = (ESS_V2, v2[0]) if v2 else (ESS_V1, v1[0])
    certs = value.expect(SEQUENCE, "SigningCertificate").children()[0]
    return version, certs.expect(SEQUENCE, "certs").children()


def ess_problem(token: Token, cert: x509.Certificate) -> str | None:
    """Why the ESS signing-certificate attribute does not bind *cert*, if it does not."""
    try:
        found = _ess_ids(token)
        if found is None:
            return "signed attributes carry no single ESS signingCertificate(V2) attribute"
        version, ids = found
        if not ids:
            return "ESS signingCertificate lists no certificate"
        parts = ids[0].expect(SEQUENCE, "ESSCertID").children()
        name = "sha1"
        if version == ESS_V2 and parts[0].tag == SEQUENCE:
            algorithm = _der.as_oid(parts[0].children()[0])
            name = HASHES.get(algorithm, "")
            parts = parts[1:]
        elif version == ESS_V2:
            name = "sha256"
        if not name:
            return "ESS signingCertificateV2 uses an unsupported hash"
        expected = parts[0].expect(OCTETS, "certHash").value
        actual = hashlib.new(name, cert.public_bytes(Encoding.DER)).digest()
        if not hmac.compare_digest(expected, actual):
            return "ESS certHash does not match the certificate that signed the token"
        if len(parts) > 1:
            serial = parts[1].expect(SEQUENCE, "IssuerSerial").children()[1]
            if _der.as_int(serial) != cert.serial_number:
                return "ESS issuerSerial names a different certificate"
    except (IndexError, ValueError) as exc:
        return f"ESS signingCertificate is malformed: {exc}"
    return None


def _unknown_critical(cert: x509.Certificate) -> str | None:
    for ext in cert.extensions:
        if ext.critical and isinstance(ext.value, x509.UnrecognizedExtension):
            return ext.oid.dotted_string
    return None


def extension_problem(token: Token, cert: x509.Certificate) -> str | None:
    """A critical TSTInfo extension or an unrecognised critical certificate extension."""
    critical = [oid for oid, flag in token.extensions if flag]
    if critical:
        return f"TSTInfo carries critical extension {critical[0]}, which is not understood"
    unknown = _unknown_critical(cert)
    return f"TSA certificate has unrecognised critical extension {unknown}" if unknown else None


def eku_problem(cert: x509.Certificate) -> str | None:
    """RFC 3161 §2.3: one EKU, critical, holding only id-kp-timeStamping."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return "TSA certificate lacks timeStamping"
    if ExtendedKeyUsageOID.TIME_STAMPING not in ext.value:
        return "TSA certificate lacks timeStamping"
    if not ext.critical:
        return "TSA certificate's timeStamping EKU is not marked critical"
    if len(list(ext.value)) != 1:
        return "TSA certificate's EKU holds purposes other than timeStamping"
    return None


def issuer_ok(parent: x509.Certificate) -> bool:
    """An issuer's KeyUsage, if any, allows keyCertSign; no unknown critical extension."""
    if _unknown_critical(parent):
        return False
    try:
        usage = parent.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return usage.key_cert_sign


__all__ = ["ESS_V1", "ESS_V2", "eku_problem", "ess_problem", "extension_problem", "issuer_ok"]
