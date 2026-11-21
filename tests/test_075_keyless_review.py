"""Review of 0.74 keyless verification: a leaf certificate must not act as a CA.

Any OIDC user can get a Fulcio leaf for their own identity. If the chain walk
accepted a non-CA certificate as an issuer, that user could sign a second leaf
naming a pinned identity with their ephemeral key and present ``[forged, own
leaf, intermediate]``. Each issuer on the path must be a CA (BasicConstraints
ca=True) allowed to sign certificates.
"""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from opentine._fulcio_verify import load_roots
from opentine._keyless_check import KeylessFail, chain_path
from tests._keyless_fixtures import WorkflowFulcio


def test_a_leaf_certificate_cannot_issue_another_leaf():
    fulcio = WorkflowFulcio(workflow=False)
    own_key = ec.generate_private_key(ec.SECP256R1())
    own = fulcio.issue(own_key.public_key())
    forged_key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    extra = (
        x509.SubjectAlternativeName([x509.RFC822Name("owner@example.com")]),
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
    )
    forged = fulcio._cert(x509.Name([]), own.subject, forged_key.public_key(), own_key,
                          now - dt.timedelta(minutes=1), now + dt.timedelta(minutes=5),
                          extra=extra)  # fmt: skip
    roots = load_roots(fulcio.roots_pem())
    assert chain_path(own, [fulcio.inter], roots)[-1] == fulcio.root
    with pytest.raises(KeylessFail) as caught:
        chain_path(forged, [own, fulcio.inter], roots)
    assert caught.value.code == "fail:keyless-chain"
