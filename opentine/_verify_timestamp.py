"""The ``timestamp`` checks of ``tine verify --offline`` (0.31.0).

One check per RFC 3161 token stored beside the run (``_timestamp_sidecar``),
each verified by :func:`opentine._tsp_verify.verify_token` against the run's
recomputed digest and the local TSA roots: ``--tsa-roots FILE.pem`` plus the
``timestampAuthorities`` of ``--trusted-root`` when one is given. With no token
and no ``--tsa-roots`` nothing is added, so older reports are unchanged.
Timestamp checks are never required: a token adds evidence of *when*, never
of *who*.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any

from opentine._verify_report import Check

NAME = "timestamp"


def _roots(args: argparse.Namespace) -> tuple[list[Any], str]:
    """``(certificates, trust basis)``; ``ValueError`` names an unreadable file."""
    from cryptography import x509

    certs: list[Any] = []
    basis: list[str] = []
    pem = getattr(args, "tsa_roots", None)
    if pem:
        raw = Path(pem).read_bytes()
        try:
            certs.extend(x509.load_pem_x509_certificates(raw))
        except ValueError:
            raise ValueError(f"--tsa-roots {Path(pem).name} holds no PEM certificate") from None
        basis.append(f"--tsa-roots {Path(pem).name} sha256 {hashlib.sha256(raw).hexdigest()}")
    trusted = getattr(args, "trusted_root", None)
    if trusted:
        from opentine._trusted_root import load_trusted_root

        tsas = load_trusted_root(trusted).timestamp_authorities
        certs.extend(cert for chain, _ in tsas for cert in chain)
        if tsas:
            basis.append(f"timestampAuthorities of {Path(trusted).name}")
    return certs, "; ".join(basis) or "none: no TSA root supplied"


def timestamp_checks(
    args: argparse.Namespace, path: Path, integrity: Any
) -> tuple[list[Check], list[dict[str, Any]]]:
    """The checks and the report's additive ``timestamps`` section."""
    from opentine import _timestamp_sidecar as sidecar
    from opentine._tsp_verify import verify_token

    asked = bool(getattr(args, "tsa_roots", None))
    try:
        entries = sidecar.load(path)
    except (OSError, ValueError) as exc:
        return [Check(NAME, "fail", "timestamp.malformed", str(exc), "none")], []
    if not entries:
        if not asked:
            return [], []
        return [Check(NAME, "not-applicable", "timestamp.absent", "no timestamp token")], []
    bound = sidecar.bound_string(integrity)
    if bound is None:
        detail = "not checked: the digest already failed"
        return [Check(NAME, "not-applicable", "timestamp.integrity-failed", detail, "none")], []
    try:
        roots, basis = _roots(args)
    except (OSError, ValueError) as exc:
        return [Check(NAME, "fail", "timestamp.roots-unreadable", str(exc), "none")], []
    checks, section = [], []
    for stored, token in entries:
        if stored != bound:
            outcome, reason, info = "fail", "timestamp.bound-mismatch", {}
            detail = f"token is bound to {stored}, the run is now {bound}"
        else:
            verdict = verify_token(token, bound.encode("utf-8"), roots)
            reason, detail, info = verdict.reason, verdict.detail, verdict.info
            outcome = "pass" if verdict.ok else "fail"
            if verdict.no_roots:
                outcome = "unavailable-offline"
        checks.append(Check(NAME, outcome, reason, detail, basis))
        section.append({"bound": stored, "outcome": outcome, "reason": reason, **info})
    return checks, section


__all__ = ["timestamp_checks"]
