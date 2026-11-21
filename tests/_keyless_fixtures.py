"""Throwaway Fulcio-like CA with workload identities, for ``tine sign --keyless`` tests.

Extends :class:`tests._sigstore_fakes.FakeFulcio` (root -> intermediate CA) with
a CI workflow identity: a URI SAN plus Fulcio's build-signer, source-repository
and ref extensions. :class:`tests._sigstore_fakes.FakeLog` is the Rekor-like
log (RFC 6962 Merkle tree, inclusion proofs, signed tree heads). No network.
"""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from tests._sigstore_fakes import IDENTITY, ISSUER_URL, FakeFulcio, _name

GH_ISSUER = "https://token.actions.example"
WORKFLOW = "https://github.example/o/r/.github/workflows/release.yml@refs/heads/main"
REPO = "https://github.example/o/r"


def utf8(text: str) -> bytes:
    raw = text.encode("utf-8")
    head = bytes([len(raw)]) if len(raw) < 0x80 else b"\x81" + bytes([len(raw)])
    return b"\x0c" + head + raw


def ext(arc: str, text: str) -> x509.UnrecognizedExtension:
    return x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.57264.1." + arc),
                                      utf8(text))  # fmt: skip


class WorkflowFulcio(FakeFulcio):
    """Issues a CI workload identity (URI SAN + build signer + source repository)."""

    def __init__(self, workflow: bool = True) -> None:
        super().__init__(identity=WORKFLOW if workflow else IDENTITY,
                         issuer=GH_ISSUER if workflow else ISSUER_URL)  # fmt: skip
        self.workflow = workflow

    def issue(self, public) -> x509.Certificate:
        if not self.workflow:
            return super().issue(public)
        now = dt.datetime.now(dt.UTC)
        extra = (
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(self.identity)]),
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            ext("8", self.issuer),
            ext("9", WORKFLOW),
            ext("11", "github-hosted"),
            ext("12", REPO),
            ext("14", "refs/heads/main"),
            ext("20", "push"),
        )
        return self._cert(x509.Name([]), _name("fake-inter"), public, self.inter_key,
                          now - dt.timedelta(minutes=1), now + dt.timedelta(minutes=10),
                          extra=extra)  # fmt: skip
