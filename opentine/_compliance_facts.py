"""The evidence facts ``tine compliance check`` maps profiles onto (0.48).

Every fact is ``{"status": "evidenced" | "missing", "detail": str}`` and is
read from a verifier OpenTine already ships, never re-derived here:

``integrity``             the offline report's ``digest`` check passed (SPEC 3.5).
``signature``             its ``signature`` check passed (any key).
``signature.authenticated`` a pass that names who signed (``authorship``): a
                          supplied, pinned or HMAC key, not one the file embeds.
``timestamp``             an RFC 3161 token verified against ``--tsa-roots``.
``transparency``          a transparency-log receipt verified (``rekor-receipt``).
``capture.independent``   the verified assurance tier is T2 or T3 (a proxy witnessed it).
``log.events``            the run records at least one step.
``log.period``            the run records a start time and every step a time.
``retention.six-months``  ``--repo``'s ``retention.toml`` keeps objects at least
                          183 days, or holds this run (``legal_hold``).
``custody``               ``--repo``'s custody log verifies and is not empty.

A fact that cannot be checked (no key, no roots, no repository) is
``missing`` with the reason, never ``evidenced``: absence of proof is not proof.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

FACTS = (
    "integrity",
    "signature",
    "signature.authenticated",
    "timestamp",
    "transparency",
    "capture.independent",
    "log.events",
    "log.period",
    "retention.six-months",
    "custody",
)
SIX_MONTHS_DAYS = 183.0
_CHECK_FACTS = {
    "integrity": "digest",
    "signature": "signature",
    "timestamp": "timestamp",
    "transparency": "rekor-receipt",
}


def _fact(ok: bool, detail: str) -> dict[str, str]:
    return {"status": "evidenced" if ok else "missing", "detail": detail}


def from_report(
    report: dict[str, Any], run: Any, signer_authenticated: bool = False
) -> dict[str, dict[str, str]]:
    """The facts a ``tine-verify-report/2`` document and the loaded run show.

    A fact is evidenced only when every check of its name passes (a run may
    carry several timestamp tokens) and the verdict is ``pass``: one failing
    check (a tampered digest, a forged token) taints every fact the report
    gives. *signer_authenticated* is True only when the ``signature`` check
    itself passed under a supplied, pinned or HMAC key; the report-wide
    ``authorship`` may come from another check (a delegation chain).
    """
    rows = [c for c in report.get("checks", []) if isinstance(c, dict)]
    good = report.get("verdict") == "pass" and report.get("ok") is True
    failed = sorted({str(c.get("name")) for c in rows if c.get("outcome") == "fail"})
    taint = "" if good else f" (but the verify verdict is fail: {', '.join(failed) or '?'})"
    facts: dict[str, dict[str, str]] = {}
    for fact, name in _CHECK_FACTS.items():
        mine = [c for c in rows if c.get("name") == name]
        if not mine:
            facts[fact] = _fact(False, f"no {name} check in the verify report")
            continue
        ok = all(c.get("outcome") == "pass" for c in mine)
        detail = "; ".join(f"{c.get('reason')}: {c.get('detail')}" for c in mine)
        facts[fact] = _fact(ok and good, detail + (taint if ok else ""))
    signed = facts["signature"]["status"] == "evidenced"
    facts["signature.authenticated"] = _fact(
        bool(signed and signer_authenticated),
        f"signer identified by {report.get('authorship')}"
        if signed and signer_authenticated
        else "no key identifies the signer "
        "(pass --pubkey or --pin; an embedded key is trust on first use)",
    )
    tier = (report.get("assurance") or {}).get("verified", "T0") if good else "T0"
    facts["capture.independent"] = _fact(tier in ("T2", "T3"), f"verified assurance tier {tier}")
    steps = list(getattr(run, "steps", []) or [])
    facts["log.events"] = _fact(bool(steps) and good, f"{len(steps)} recorded step(s){taint}")
    started = bool(getattr(run, "created_at", 0))
    timed = bool(steps) and all(getattr(s, "timestamp", 0) for s in steps)
    facts["log.period"] = _fact(
        started and timed and good,
        "start time and a time on every step" if started and timed else
        "the run lacks a start time or a step lacks a time",
    )  # fmt: skip
    return facts


def repo_facts(repo_path: str | None, run_digest: str | None) -> dict[str, dict[str, str]]:
    """``retention.six-months`` and ``custody`` for ``--repo`` (missing without one)."""
    if not repo_path:
        why = "no --repo: no retention policy or custody log was examined"
        return {"retention.six-months": _fact(False, why), "custody": _fact(False, why)}
    from opentine._cli_du import _repo

    try:
        repo = _repo(repo_path)
    except (KeyError, OSError, ValueError) as exc:
        why = f"--repo unreadable: {exc}"
        return {"retention.six-months": _fact(False, why), "custody": _fact(False, why)}
    return {"retention.six-months": _retention(repo, run_digest), "custody": _custody(repo)}


def _retention(repo: Any, run_digest: str | None) -> dict[str, str]:
    from opentine._retention import RetentionPolicy

    try:
        policy = RetentionPolicy.for_repo(repo)
    except (OSError, ValueError) as exc:
        return _fact(False, f"retention.toml unreadable: {exc}")
    want = _bare(run_digest)
    held = bool(want) and any(_bare(oid) == want for oid in policy.legal_hold)
    if held:
        return _fact(True, "the run is under legal_hold")
    days = float(policy.keep_days)
    return _fact(days >= SIX_MONTHS_DAYS, f"keep_days = {days:g} (needs >= {SIX_MONTHS_DAYS:g})")


def _bare(oid: str | None) -> str:
    """``run:sha256:HEX``, ``sha256:HEX`` or ``HEX`` as lowercase hex: whole digests match."""
    return (oid or "").strip().lower().rsplit(":", 1)[-1]


def _custody(repo: Any) -> dict[str, str]:
    from opentine import _custody

    try:
        result = _custody.verify(Path(repo.path), argparse.Namespace())
    except Exception as exc:  # LogError, OSError, ValueError: any refusal is "missing"
        return _fact(False, f"custody log does not verify: {exc}")
    size = int(result.get("size", 0))
    return _fact(size > 0, f"{size} verified custody record(s)")


__all__ = ["FACTS", "SIX_MONTHS_DAYS", "from_report", "repo_facts"]
