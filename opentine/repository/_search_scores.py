"""Which evaluation decides a run's search score.

Split out of ``search`` for the module line cap. Search ranked a run by the
*max* over every evaluation attestation targeting it, and anyone who can write
an attestation -- an MCP client, i.e. a model reading untrusted run content --
could write an unsigned one: ``evaluate_run(R, {"quality": 1.7e308})`` put R
first and through every ``min_score``. A signed evaluation now outranks any
unsigned one: when a run has signed evaluations its score is the best of
those, and unsigned scores count only for runs with none (or not at all, with
``signed_only``), and a run scored by a signed evaluation ranks above every run
scored by an unsigned one. ``score_signed`` reports which kind decided.

"Signed" means the attestation carries a well-formed signature block (one that
verifies to ``no-key`` without a key: ``"signature": {}`` is junk, not a
signature). Search holds no keys, so this is not verification -- ``tine
repo-verify`` with a trusted key is. An unsigned score outside +/-1e6 -- the
bound MCP ``evaluate_run`` enforces, which ``attest_run`` or any repository
writer could skip -- counts for nothing.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from opentine.attest_signing import verify_attestation

#: The largest unsigned evaluation score search believes (MCP's ``evaluate_run`` bound).
MAX_UNSIGNED_SCORE = 1e6

#: target run id -> [(average score, signed)]
Scores = dict[str, list[tuple[float, bool]]]


def collect_scores(
    oids: Iterable[str],
    payload_of: Callable[[str], dict[str, Any] | None],
    finite: Callable[[Any], float | None],
) -> Scores:
    scores: Scores = {}
    for oid in oids:
        if not oid.startswith("attestation:"):
            continue
        payload = payload_of(oid)
        if payload is None:
            continue
        claim = payload.get("claim") or {}
        if not isinstance(claim, dict) or not isinstance(claim.get("scores") or {}, dict):
            continue
        if claim.get("kind") != "evaluation":
            continue
        values = [
            number
            for value in (claim.get("scores") or {}).values()
            if (number := finite(value)) is not None
        ]
        target = payload.get("target_id")
        average = finite(sum(values) / len(values)) if values else None
        if isinstance(target, str) and average is not None:
            signed = _signed(payload)
            if not signed and any(abs(value) > MAX_UNSIGNED_SCORE for value in values):
                continue
            scores.setdefault(target, []).append((average, signed))
    return scores


def _signed(payload: dict[str, Any]) -> bool:
    return verify_attestation(payload).state not in ("error", "unsigned")


def best_score(
    entries: list[tuple[float, bool]], *, signed_only: bool
) -> tuple[float | None, bool | None]:
    """``(score, score_signed)`` for one run; ``(None, None)`` when nothing counts."""
    signed = [average for average, is_signed in entries if is_signed]
    if signed:
        return max(signed), True
    if signed_only or not entries:
        return None, None
    return max(average for average, _ in entries), False


__all__ = ["MAX_UNSIGNED_SCORE", "Scores", "best_score", "collect_scores"]
