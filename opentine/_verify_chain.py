"""One run through every offline check: the report ``tine verify --offline`` emits.

Order: digest, signature, attestation family, action manifest and policy, the
claim-to-tool-output cross-check, then (with ``--locate``) localisation. The
whole chain runs under ``_offline_guard.no_network``.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._verify_report import Check, Report


def build_report(args: argparse.Namespace, path: Path | None, target: str) -> Report:
    from opentine._offline_guard import NetworkRefused, no_network

    report = Report(str(path or target), strict=bool(getattr(args, "strict", False)))
    if path is None:
        report.add(Check("digest", "fail", "digest.unreadable", f"run not found: {target}"))
        return report
    try:
        with no_network():
            _chain(args, path, report)
    except NetworkRefused as exc:
        report.add(Check("network", "fail", "offline.network-refused", str(exc), "none", True))
    return report


def _read(path: Path) -> tuple[Any, Any]:
    """``(artifact dict | None, Run | None)``: the run even when its digest broke."""
    from opentine._artifact_io import read_artifact_json
    from opentine._graph_serde import run_from_dict
    from opentine.core import Run

    try:
        data = read_artifact_json(path)
    except (OSError, RecursionError, ValueError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    try:
        return data, run_from_dict(data, Run)
    except Exception:
        return data, None


def _manifest(args: argparse.Namespace, data: Any) -> Any:
    from opentine import _cli_who_trust as who_trust
    from opentine._actions_verdict import load_manifest

    run_id = data.get("run_id") if isinstance(data, dict) else None
    if not isinstance(run_id, str):
        return None
    _, base, _ = who_trust.scope_paths(args)
    return load_manifest(base, run_id)


def _attested_digest(args: argparse.Namespace, report: Report) -> str | None:
    """The subject of an attestation whose signature verified under a supplied key.

    TOFU and keyless statuses are not accepted here: only ``attestation.verified``
    (or a verified signature whose subject then mismatched).
    """
    signed = ("attestation.verified", "attestation.subject-mismatch")
    if not any(
        c.name == "attestation" and c.reason in signed and "first-use" not in c.trust_basis
        for c in report.checks
    ):
        return None
    from opentine.intoto import _b64, _statement, read_envelopes
    from opentine.sigstore_bundle import split

    try:
        envelope, _, _ = split(read_envelopes(args.attestation)[0])
        statement = _statement(_b64(envelope.get("payload")))
        return (statement.get("subject") or [{}])[0].get("digest", {}).get("sha256")
    except (OSError, ValueError, IndexError, AttributeError):
        return None


def _chain(args: argparse.Namespace, path: Path, report: Report) -> None:
    from opentine._verify_claims import claims_check
    from opentine._verify_offline import actions_checks, digest_check, signature_check
    from opentine._verify_offline_attest import attestation_checks

    digest, integrity = digest_check(path)
    report.add(digest)
    signature = signature_check(args, path, integrity.ok)
    report.add(signature)
    for check in attestation_checks(args, path):
        report.add(check)
    data, run = _read(path)
    for check in actions_checks(args, run if integrity.ok else None):
        report.add(check)
    stored = _manifest(args, data)
    claims = claims_check(stored, data, run)
    report.add(claims)
    if getattr(args, "locate", False):
        from opentine._verify_locate import locate

        report.location = locate(
            data,
            integrity,
            signature_ok=None if signature.outcome != "fail" else False,
            manifest=stored,
            run=run,
            attested_digest=_attested_digest(args, report),
            claims=claims,
        )


__all__ = ["build_report"]
