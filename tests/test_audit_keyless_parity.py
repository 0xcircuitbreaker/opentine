"""Audit OT-12 / OT-13: ``tine verify`` and ``tine keyless verify`` agree.

Both verifiers must read the same leaf from ``verificationMaterial`` (and
refuse a material that carries more than one of the Sigstore one-of keys), and
must walk the chain with the same depth limit and the same CA checks.
"""

from __future__ import annotations

import base64
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from opentine import _keyless_check
from opentine._fulcio_verify import leaf_from_material, verify_keyless
from opentine.intoto import PAYLOAD_TYPE, pae
from tests._sigstore_fakes import IDENTITY, ISSUER_URL, FakeFulcio, _name

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def _raw(cert: x509.Certificate) -> dict:
    return {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()}


def _leaf(fulcio: FakeFulcio) -> x509.Certificate:
    return fulcio.issue(ec.generate_private_key(ec.SECP256R1()).public_key())


def _keyless_leaf(material):
    try:
        return _keyless_check.certificates(material)[0]
    except ValueError:
        return "refused"


def _fulcio_leaf(material):
    try:
        return leaf_from_material(material)
    except ValueError:
        return "refused"


def test_ot12_both_verifiers_refuse_certificate_plus_chain():
    a, b = _leaf(FakeFulcio()), _leaf(FakeFulcio())
    material = {"certificate": _raw(b), "x509CertificateChain": {"certificates": [_raw(a)]}}
    assert _fulcio_leaf(material) == "refused"
    assert _keyless_leaf(material) == "refused"


@pytest.mark.parametrize("extra", [{"publicKey": {"hint": "k"}}, {}])
def test_ot12_both_verifiers_pick_the_same_leaf(extra):
    a = _leaf(FakeFulcio())
    chain = {"x509CertificateChain": {"certificates": [_raw(a)]}}
    for material in ({"certificate": _raw(a)}, chain):
        material = {**material, **extra}
        assert _fulcio_leaf(material) == _keyless_leaf(material)


def _ca_chain(depth: int, *, ca: bool = True):
    """root, then *depth* intermediates (the last one issues the leaf)."""
    key = ec.generate_private_key(ec.SECP256R1())
    start, end = NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=1)
    root = FakeFulcio._cert(_name("r"), _name("r"), key.public_key(), key, start, end, ca=True)
    chain, issuer, issuer_key = [root], _name("r"), key
    for i in range(depth):
        k = ec.generate_private_key(ec.SECP256R1())
        chain.append(FakeFulcio._cert(_name(f"i{i}"), issuer, k.public_key(), issuer_key,
                                      start, end, ca=ca))  # fmt: skip
        issuer, issuer_key = _name(f"i{i}"), k
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    issuer_der = b"\x0c" + bytes([len(ISSUER_URL)]) + ISSUER_URL.encode()
    extra = (
        x509.SubjectAlternativeName([x509.RFC822Name(IDENTITY)]),
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
        x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.8"), issuer_der),
    )
    leaf = FakeFulcio._cert(x509.Name([]), issuer, leaf_key.public_key(), issuer_key,
                            start, end, extra=extra)  # fmt: skip
    return leaf, leaf_key, chain


def _fulcio_verdict(leaf, leaf_key, roots) -> bool:
    body = b"{}"
    sig = leaf_key.sign(pae(PAYLOAD_TYPE, body), ec.ECDSA(hashes.SHA256()))
    envelope = {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(body).decode(),
                "signatures": [{"sig": base64.b64encode(sig).decode()}]}  # fmt: skip
    try:
        verify_keyless(envelope, leaf, roots=roots, identity=IDENTITY, issuer=ISSUER_URL,
                       integrated_time=int(NOW.timestamp()))  # fmt: skip
    except ValueError:
        return False
    return True


def _keyless_verdict(leaf, roots) -> bool:
    try:
        _keyless_check.chain_path(leaf, [], roots)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("depth", [1, 2, 3, 4])
def test_ot13_same_depth_limit_in_both_verifiers(depth):
    leaf, key, roots = _ca_chain(depth)
    assert _fulcio_verdict(leaf, key, roots) == _keyless_verdict(leaf, roots)


def test_ot13_three_intermediates_accepted_by_both():
    leaf, key, roots = _ca_chain(3)
    assert _keyless_verdict(leaf, roots) and _fulcio_verdict(leaf, key, roots)


def test_ot13_non_ca_issuer_refused_by_both():
    leaf, key, roots = _ca_chain(1, ca=False)
    assert not _keyless_verdict(leaf, roots)
    assert not _fulcio_verdict(leaf, key, roots)
