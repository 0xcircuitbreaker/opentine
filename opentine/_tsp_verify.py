"""Verify an RFC 3161 timestamp token offline, against local trust anchors only.

:func:`verify_token` checks, in order: the DER parses; the messageImprint is
the token's hash of the bound bytes; the signed attributes name a TSTInfo and
carry its digest; the TSA signature over the signed attributes; the TSA
certificate has the timestamping EKU and genTime lies within its validity;
and the certificate chains (each link's signature, CA flag and validity at
genTime) to one of the supplied roots. The first failed step is the verdict.

Roots from a trusted root's ``timestampAuthorities`` come with their
``validFor`` window (0.35.0): such an authority is an anchor only for tokens
whose genTime lies inside the window. A token minted before an authority was
retired keeps verifying; one dated after ``validFor.end`` (or before
``validFor.start``) fails closed with ``timestamp.tsa-retired``.
Nothing here opens a connection or fetches a certificate.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from opentine import _der
from opentine._tsp import ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST, HASHES, TST_INFO, Token, parse

_PSS = "1.2.840.113549.1.1.10"
_MAX_CHAIN = 8


@dataclass
class Verdict:
    ok: bool
    reason: str
    detail: str
    #: Report fields; filled as far as parsing got.
    info: dict[str, Any] = field(default_factory=dict)
    #: True when only the trust anchor was missing (unavailable, not a forgery).
    no_roots: bool = False


def _when(cert: x509.Certificate) -> tuple[datetime, datetime]:
    return cert.not_valid_before_utc, cert.not_valid_after_utc


def _signer_cert(token: Token) -> x509.Certificate:
    for der in token.certs:
        cert = x509.load_der_x509_certificate(der)
        if token.signer_ski is not None:
            try:
                ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            except x509.ExtensionNotFound:
                continue
            if ski.value.digest == token.signer_ski:
                return cert
        elif (
            cert.serial_number == token.signer_serial
            and cert.issuer.public_bytes() == token.signer_issuer
        ):
            return cert
    raise ValueError("the token carries no certificate for its signer")


def _check_signature(token: Token, cert: x509.Certificate) -> None:
    name = HASHES.get(token.digest_oid)
    if name is None or token.sig_oid == _PSS:
        raise TypeError("unsupported signature or digest algorithm")
    algorithm = getattr(hashes, name.upper())()
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key.verify(token.signature, token.signed_attrs, padding.PKCS1v15(), algorithm)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(token.signature, token.signed_attrs, ec.ECDSA(algorithm))
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key.verify(token.signature, token.signed_attrs)
    else:
        raise TypeError("unsupported TSA key type")


def _attrs_ok(token: Token) -> bool:
    name = HASHES.get(token.digest_oid)
    kind = token.attrs.get(ATTR_CONTENT_TYPE) or []
    digest = token.attrs.get(ATTR_MESSAGE_DIGEST) or []
    if name is None or len(kind) != 1 or len(digest) != 1:
        return False
    expected = hashlib.new(name, token.tst_info).digest()
    return _der.as_oid(kind[0]) == TST_INFO and hmac.compare_digest(digest[0].value, expected)


def _chain(leaf: x509.Certificate, pool: list[x509.Certificate], roots, when) -> bool:
    anchors = {root.public_bytes(Encoding.DER): root for root in roots}
    current = leaf
    for _ in range(_MAX_CHAIN):
        if current.public_bytes(Encoding.DER) in anchors:
            return True
        issuers = [c for c in [*roots, *pool] if c.subject == current.issuer]
        nxt = next((c for c in issuers if _issued(current, c, when)), None)
        if nxt is None:
            return False
        current = nxt
    return False


def _issued(child: x509.Certificate, parent: x509.Certificate, when: datetime) -> bool:
    try:
        child.verify_directly_issued_by(parent)
        basic = parent.extensions.get_extension_for_class(x509.BasicConstraints).value
    except (InvalidSignature, ValueError, TypeError, x509.ExtensionNotFound):
        return False
    start, end = _when(parent)
    return basic.ca and start <= when <= end


def verify_token(
    data: bytes,
    bound: bytes,
    roots: list[x509.Certificate],
    windowed: Sequence[tuple[list[x509.Certificate], Any]] = (),
) -> Verdict:
    """*windowed* holds ``(chain, window)`` anchors trusted only for a genTime
    the window contains."""
    try:
        token = parse(data)
    except ValueError as exc:
        return Verdict(False, "timestamp.malformed", f"not an RFC 3161 token: {exc}")
    info = {
        "gen_time": token.gen_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "policy": token.policy,
        "hash_algorithm": token.hash_name,
        "serial": str(token.serial),
        "tsa": None,
    }
    if token.hash_oid not in HASHES:
        return Verdict(False, "timestamp.unsupported-algorithm", "unsupported imprint hash", info)
    if not hmac.compare_digest(hashlib.new(token.hash_name, bound).digest(), token.imprint):
        detail = f"messageImprint is not the {token.hash_name} of the run's bound digest"
        return Verdict(False, "timestamp.imprint-mismatch", detail, info)
    try:
        cert = _signer_cert(token)
        pool = [x509.load_der_x509_certificate(der) for der in token.certs]
    except ValueError as exc:
        return Verdict(False, "timestamp.malformed", str(exc), info)
    info["tsa"] = cert.subject.rfc4514_string()
    try:
        if not _attrs_ok(token):
            return Verdict(False, "timestamp.bad-signature", "signed attributes mismatch", info)
        _check_signature(token, cert)
    except TypeError as exc:
        return Verdict(False, "timestamp.unsupported-algorithm", str(exc), info)
    except (InvalidSignature, ValueError):
        return Verdict(False, "timestamp.bad-signature", "TSA signature does not verify", info)
    try:
        usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usage = []
    if ExtendedKeyUsageOID.TIME_STAMPING not in usage:
        return Verdict(False, "timestamp.missing-eku", "TSA certificate lacks timeStamping", info)
    start, end = _when(cert)
    if not start <= token.gen_time <= end:
        return Verdict(False, "timestamp.outside-validity", "genTime outside cert validity", info)
    live = [c for chain, window in windowed if window.contains(token.gen_time) for c in chain]
    if windowed and not roots and not live:
        detail = f"genTime {info['gen_time']} is outside every TSA validFor window"
        return Verdict(False, "timestamp.tsa-retired", detail, info)
    roots = [*roots, *live]
    if not roots:
        detail = "no TSA root supplied: pass --tsa-roots FILE.pem"
        return Verdict(False, "timestamp.no-roots", detail, info, no_roots=True)
    if not _chain(cert, pool, roots, token.gen_time):
        return Verdict(False, "timestamp.untrusted-root", "TSA chain reaches no trusted root", info)
    detail = f"genTime {info['gen_time']} by {info['tsa']} ({token.hash_name})"
    return Verdict(True, "timestamp.verified", detail, info)


__all__ = ["Verdict", "verify_token"]
