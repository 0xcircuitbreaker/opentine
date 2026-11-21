"""Leaf selection and chain walk shared by both keyless verifiers.

``tine verify`` (via :mod:`opentine._fulcio_verify`) and ``tine keyless
verify`` (via :mod:`opentine._keyless_check`) must read the same signing
certificate from a bundle and accept the same chains, or the two commands
could name different signers or give opposite verdicts for one bundle.

* ``verificationMaterial`` must carry exactly one of ``certificate``,
  ``x509CertificateChain`` and ``publicKey`` (the Sigstore one-of); a bundle
  with more than one is refused as malformed.
* The chain walk allows at most :data:`MAX_DEPTH` certificates from the leaf
  to a self-signed root in the trust root, and each issuer on the path must be
  a CA (BasicConstraints ``ca``) allowed to sign certificates (KeyUsage).
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature

MAX_DEPTH = 5
_ONE_OF = ("certificate", "x509CertificateChain", "publicKey")


class KeylessFail(ValueError):
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code


def _der(item: Any) -> x509.Certificate:
    raw = item.get("rawBytes") if isinstance(item, dict) else None
    try:
        return x509.load_der_x509_certificate(base64.b64decode(str(raw), validate=True))
    except (ValueError, binascii.Error) as exc:
        raise KeylessFail("fail:keyless-malformed", f"certificate is malformed: {exc}") from None


def certificates(material: Any) -> list[x509.Certificate]:
    """Leaf first, then any bundled intermediates; refuses an ambiguous material."""
    if not isinstance(material, dict):
        raise KeylessFail("fail:keyless-malformed", "verificationMaterial is not an object")
    present = [k for k in _ONE_OF if k in material]
    if len(present) > 1:
        reason = f"verificationMaterial carries more than one of {', '.join(_ONE_OF)}"
        raise KeylessFail("fail:keyless-malformed", reason)
    if "x509CertificateChain" in material:
        chain = material["x509CertificateChain"]
        items = chain.get("certificates") if isinstance(chain, dict) else None
        if not isinstance(items, list) or not items:
            raise KeylessFail("fail:keyless-malformed", "x509CertificateChain has no certificates")
        return [_der(i) for i in items]
    if "certificate" in material:
        return [_der(material["certificate"])]
    raise KeylessFail("fail:keyless-not-keyless", "bundle carries no signing certificate")


def _is_ca(cert: x509.Certificate) -> bool:
    """A certificate may issue others only as a CA allowed to sign certificates."""
    try:
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return False
    except x509.ExtensionNotFound:
        return False
    try:
        return cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    except x509.ExtensionNotFound:
        return True


def _issued_by(cert: x509.Certificate, candidate: x509.Certificate) -> bool:
    if candidate.subject != cert.issuer or not _is_ca(candidate):
        return False
    try:
        cert.verify_directly_issued_by(candidate)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def chain_path(leaf, extra: list, roots: list) -> list[x509.Certificate]:
    """leaf .. root, each signed by the next; the root must be self-signed and in *roots*."""
    path, cert = [leaf], leaf
    for _ in range(MAX_DEPTH):
        if cert in roots and cert.issuer == cert.subject:
            return path
        pool = roots + [c for c in extra if c.issuer != c.subject]
        nxt = next((c for c in pool if c not in path and _issued_by(cert, c)), None)
        if nxt is None:
            raise KeylessFail("fail:keyless-chain", "certificate does not chain to the trust root")
        path.append(nxt)
        cert = nxt
    raise KeylessFail("fail:keyless-chain", "certificate chain is too long")


__all__ = ["MAX_DEPTH", "KeylessFail", "certificates", "chain_path"]
