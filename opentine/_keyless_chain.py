"""Leaf selection shared by both keyless verifiers.

``tine verify`` (via :mod:`opentine._fulcio_verify`) and ``tine keyless
verify`` (via :mod:`opentine._keyless_check`) must read the same signing
certificate from a bundle, or the two commands could name different signers
for one bundle.

* ``verificationMaterial`` must carry exactly one of ``certificate``,
  ``x509CertificateChain`` and ``publicKey`` (the Sigstore one-of); a bundle
  with more than one is refused as malformed.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography import x509

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


__all__ = ["KeylessFail", "certificates"]
