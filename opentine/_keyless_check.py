"""Offline verification of a keyless run signature (0.74, ``tine keyless verify``).

The evidence is the existing Sigstore bundle v0.3 (``tine sign --keyless``,
``tine export --format intoto --keyless``): a DSSE envelope over the run's
in-toto statement, ``verificationMaterial.x509CertificateChain`` (leaf, then
intermediates) or ``certificate`` (leaf), and ``tlogEntries`` whose receipt
carries the SET, the Merkle inclusion proof and the signed tree head
(checkpoint). No new object kind: this module only reads that bundle.

Order, fail closed: the receipt (SET, inclusion proof recomputed to the root
the signed tree head names, logged body = this envelope and this leaf key)
gives the *integrated time*; the DSSE signature must verify under the leaf; the
leaf must be code-signing and chain, signature by signature, to a self-signed
root in the trust root. Only then is time considered: every certificate on the
path must be valid at the integrated time, else ``caveat:keyless-outside-window``
(the signature is real but not trusted). Last, identity: trusted only when a
pin names the exact issuer and identity, else ``caveat:keyless-unpinned``.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from opentine._keyless_chain import KeylessFail, certificates, chain_path
from opentine._keyless_identity import facts, pinned_by, tier
from opentine.intoto import PAYLOAD_TYPE, _statement, pae
from opentine.sigstore_bundle import check_entry, split


def _signature(envelope: dict, leaf: x509.Certificate) -> dict[str, Any]:
    key = leaf.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise KeylessFail("fail:keyless-signature", "certificate key is not ECDSA")
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise KeylessFail("fail:keyless-malformed", f"payloadType must be {PAYLOAD_TYPE}")
    try:
        body = base64.b64decode(str(envelope.get("payload", "")), validate=True)
        sigs = [base64.b64decode(str(s.get("sig")), validate=True) for s in envelope["signatures"]]
    except (AttributeError, KeyError, TypeError, binascii.Error) as exc:
        raise KeylessFail("fail:keyless-malformed", f"envelope is malformed: {exc}") from None
    for sig in sigs:
        try:
            key.verify(sig, pae(PAYLOAD_TYPE, body), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            continue
        try:
            return _statement(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise KeylessFail("fail:keyless-malformed", f"statement: {exc}") from None
    raise KeylessFail("fail:keyless-signature", "no signature verifies under the certificate key")


def _stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def check(document: Any, *, roots: list, log_key: Any, pins: list[dict]) -> dict[str, Any]:
    """The verdict row for one bundle; raises :class:`KeylessFail` on a failed check."""
    try:
        envelope, material, entries = split(document)
    except ValueError as exc:
        raise KeylessFail("fail:keyless-malformed", str(exc)) from None
    chain = certificates(material)
    leaf = chain[0]
    if not entries:
        raise KeylessFail("fail:keyless-receipt", "bundle carries no transparency-log entry")
    results = [check_entry(e, envelope, leaf.public_key(), log_key) for e in entries]
    receipt = next((r for r in results if r.ok), results[0])
    if not receipt.ok or receipt.integrated_time is None:
        raise KeylessFail("fail:keyless-receipt", receipt.reason)
    statement = _signature(envelope, leaf)
    try:
        usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usage = []
    if ExtendedKeyUsageOID.CODE_SIGNING not in usage:
        raise KeylessFail("fail:keyless-chain", "certificate is not a code-signing certificate")
    path = chain_path(leaf, chain[1:], roots)
    when = datetime.fromtimestamp(receipt.integrated_time, tz=UTC)
    identity = facts(leaf)
    row: dict[str, Any] = {
        "identity": identity,
        "assurance_tier": tier(identity),
        "integrated_time": _stamp(when),
        "log_index": receipt.log_index,
        "not_before": _stamp(leaf.not_valid_before_utc),
        "not_after": _stamp(leaf.not_valid_after_utc),
        "subject": statement["subject"][0],
        "trusted": False,
    }
    outside = [c for c in path if not c.not_valid_before_utc <= when <= c.not_valid_after_utc]
    if outside:
        reason = "the log's integrated time is outside a certificate's validity window"
        return {**row, "outcome": "caveat", "code": "caveat:keyless-outside-window",
                "reason": reason}  # fmt: skip
    pin = pinned_by(identity, pins)
    if pin is None:
        reason = "no owner-pinned trust bundle entry names this issuer and identity"
        return {**row, "outcome": "caveat", "code": "caveat:keyless-unpinned", "reason": reason}
    return {**row, "trusted": True, "outcome": "pass", "code": "keyless.trusted",
            "reason": "verified; identity pinned by the owner's trust bundle"}  # fmt: skip


__all__ = ["KeylessFail", "certificates", "chain_path", "check"]
