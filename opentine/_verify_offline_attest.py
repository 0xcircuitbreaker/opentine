"""Offline attestation, Rekor-receipt, certificate-chain and SCT checks.

Only material already on disk is consulted: the ``--attestation`` file and the
receipts it carries, and the keys and roots the operator names (``--pubkey``,
``--pin``, ``--rekor-key``, ``--fulcio-root``, ``--ct-key``, ``--trusted-root``,
or the TUF copy ``tine trust root update`` installed). Nothing is fetched: a
receipt the file does not carry is not looked up in the log, and a root that
was not supplied is reported ``unavailable-offline``. The verification itself
is ``_cli_intoto``'s, unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any

from opentine._verify_report import INTERNAL_ONLY, Check

NAMES = ("attestation", "rekor-receipt", "certificate", "sct")
_NONE = "none: no trusted key or root supplied"


def _file_basis(label: str, file: str | None) -> str:
    if not file:
        return _NONE
    try:
        digest = hashlib.sha256(Path(file).read_bytes()).hexdigest()
    except OSError:
        return f"{label} {file} (unreadable)"
    return f"{label} sha256 {digest}"


def _root_basis(args: argparse.Namespace) -> str:
    from opentine._keyless_root import trusted_root_path

    root = trusted_root_path(args)
    if root:
        return _file_basis("trusted_root.json", root)
    return _file_basis("fulcio root", getattr(args, "fulcio_root", None))


def _root_lists_ct_logs(args: argparse.Namespace) -> bool:
    """Whether the trusted root in force names a CT log (else no SCT was checked)."""
    from opentine._keyless_root import trusted_root_path
    from opentine._trusted_root import load_trusted_root

    root = trusted_root_path(args)
    try:
        return bool(root and load_trusted_root(root).ctlogs)
    except (OSError, ValueError):
        return False


def _skip(reason: str, detail: str) -> list[Check]:
    return [Check(name, "not-applicable", reason, detail, "none") for name in NAMES]


def attestation_checks(args: argparse.Namespace, path: Path | None) -> list[Check]:
    from opentine._cli_intoto import _check
    from opentine._fulcio_verify import leaf_from_material
    from opentine.intoto import check_subject, read_envelopes
    from opentine.sigstore_bundle import split

    file = getattr(args, "attestation", None)
    if not file:
        return _skip("attestation.none", "no --attestation given")
    try:
        envelopes = read_envelopes(file)
        if len(envelopes) != 1:
            raise ValueError(f"expected one envelope, found {len(envelopes)}")
        envelope, material, entries = split(envelopes[0])
        keyless = leaf_from_material(material) is not None
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        bad = Check("attestation", "fail", "attestation.unreadable", str(exc), "none", True)
        return [bad, *_skip("attestation.unreadable", "attestation unreadable")[1:]]
    keyed = any(getattr(args, d, None) for d in ("pubkey", "pin", "trust_embedded_key"))
    if not keyless and not keyed:
        detail = "no trusted key: pass --pubkey, --pin or --trust-embedded-key"
        return [
            Check("attestation", "unavailable-offline", "attestation.no-key", detail, _NONE, True),
            _receipt(args, None, bool(entries), keyless),
            *_skip("certificate.not-keyless", "signed by a key, not a certificate")[2:],
        ]
    try:
        result, receipt = _check(args, envelopes[0])
    except ValueError as exc:
        bad = Check("attestation", "fail", "attestation.unreadable", str(exc), "none", True)
        return [bad, *_skip("attestation.unreadable", "attestation unreadable")[1:]]
    checks = [_envelope(args, result, path, check_subject, keyless)]
    checks.append(_receipt(args, receipt, bool(entries), keyless))
    return checks + _keyless(args, result, keyless)


def _envelope(args, result, path, check_subject, keyless: bool) -> Check:
    status = result.status
    tofu = status == "verified-tofu"
    if keyless:
        basis = _root_basis(args)
    elif getattr(args, "pubkey", None):
        basis = f"supplied key {result.key_fingerprint or '-'} (--pubkey)"
    elif tofu:
        basis = f"embedded did:key, trust-on-first-use: {INTERNAL_ONLY}"
    else:
        basis = f"pinned key {result.key_fingerprint or '-'} (--pin)"
    if not result.ok:
        outcome = "unavailable-offline" if status == "no-key" else "fail"
        return Check("attestation", outcome, f"attestation.{status}", result.reason, basis, True)
    error = check_subject(result.statement, path) if path else "run not found"
    if error:
        return Check("attestation", "fail", "attestation.subject-mismatch", error, basis, True)
    detail = f"{status}; subject matches the run digest"
    return Check("attestation", "pass", f"attestation.{status}", detail, basis, True, not tofu)


def _receipt(args: argparse.Namespace, receipt: Any, carried: bool, keyless: bool) -> Check:
    required = bool(getattr(args, "require_receipt", False)) or keyless
    rekor_key = getattr(args, "rekor_key", None)
    basis = _root_basis(args) if keyless and not rekor_key else _file_basis("rekor key", rekor_key)
    if receipt is None:
        if not carried:
            outcome = "fail" if required else "not-applicable"
            return Check("rekor-receipt", outcome, "receipt.absent", "no receipt", "none", required)
        detail = "the attestation's signature was not verified, so its receipt was not checked"
        return Check("rekor-receipt", "unavailable-offline", "receipt.unchecked", detail, basis)
    status = receipt.status
    if status == "verified":
        outcome = "pass"
    elif status in ("unchecked", "no-key"):
        outcome = "unavailable-offline"
    elif status == "absent":
        outcome = "fail" if required else "not-applicable"
    else:
        outcome = "fail"
    detail = f"{receipt.reason} (stored receipt only; the log was not contacted)"
    return Check("rekor-receipt", outcome, f"receipt.{status}", detail, basis, required)


def _keyless(args: argparse.Namespace, result: Any, keyless: bool) -> list[Check]:
    if not keyless:
        return _skip("certificate.not-keyless", "signed by a key, not a certificate")[2:]
    basis = _root_basis(args)
    if result.status == "verified-keyless":
        cert = Check(
            "certificate", "pass", "certificate.verified", "chain and identity", basis, True
        )
    else:
        outcome = "unavailable-offline" if result.status == "no-key" else "fail"
        cert = Check("certificate", outcome, f"certificate.{result.status}", result.reason, basis)
    need_sct = bool(getattr(args, "require_sct", False))
    sources = getattr(args, "ct_key", None) or _root_lists_ct_logs(args)
    if not result.ok:
        sct = Check(
            "sct", "not-applicable", "sct.not-reached", "certificate failed", basis, need_sct
        )
    elif sources:
        sct = Check("sct", "pass", "sct.verified", "embedded SCT checked", basis, need_sct)
    else:
        detail = "no CT log key supplied: pass --ct-key or --trusted-root"
        sct = Check("sct", "unavailable-offline", "sct.no-key", detail, _NONE, need_sct)
    return [cert, sct]


__all__ = ["NAMES", "attestation_checks"]
