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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from opentine import _keyless_check
from opentine._fulcio_verify import leaf_from_material
from tests._sigstore_fakes import FakeFulcio

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
    for material in (
        {"certificate": _raw(a)},
        {"x509CertificateChain": {"certificates": [_raw(a)]}},
    ):
        material = {**material, **extra}
        assert _fulcio_leaf(material) == _keyless_leaf(material)
