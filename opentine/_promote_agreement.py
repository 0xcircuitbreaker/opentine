"""Judge agreement in ``tine promote`` (0.89): a judged candidate needs a judge humans agree with.

When the candidate's signed verdicts name a judge (an ``llm-judge`` scorer's
``scorer_version`` is its ``jp1+sha256:`` pin, :mod:`opentine._judge_provenance`),
every such judge must pass. The
gate looks for that judge's first reveal in the repository's label queues
(``REPO/.tine/labels/*``), re-verifies the queue and recomputes the agreement
report with the policy's ``seed`` and ``resamples`` (nothing is taken from a
stored report). The judge passes when its kappa lower bound against the human
consensus is at least ``agreement_floor`` (default ``0.6``) with enough coverage
and items (:mod:`opentine._label_report`).

``judge_agreement = "required"`` (on under ``profile = "rsi"``) refuses with
``promote.judge-agreement`` when no queue revealed the judge, the queue does
not verify, or the floor fails -- a missing record never passes. Otherwise
(``"advisory"``, the default, D12) the same finding is
``advisory:promote.judge-agreement`` and never blocks. A candidate without a
judge is not affected.
"""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Any

MODES = ("advisory", "required")
CODE = "promote.judge-agreement"
UNPINNED = "llm-judge (no provenance pin)"  # a judge verdict without jp1 never passes


def check_policy(policy: dict[str, Any]) -> None:
    rsi = policy.get("profile") == "rsi"
    mode = policy.get("judge_agreement", "required" if rsi else "advisory")
    if mode not in MODES or (rsi and mode != "required"):
        raise ValueError('judge_agreement is "advisory" or "required"; the rsi profile '
                         "requires it")  # fmt: skip
    policy["judge_agreement"] = mode
    from opentine._label_report import DECIMAL

    floor = str(policy.get("agreement_floor", "0.6"))
    ok = bool(DECIMAL.fullmatch(floor)) and 0 <= Fraction(floor) <= 1
    if not ok:
        raise ValueError("agreement_floor is a decimal in [0, 1]")
    policy["agreement_floor"] = floor
    from opentine._label_report import settings

    settings(floor=floor, min_items=policy.get("agreement_min_items"),
             min_coverage=policy.get("agreement_min_coverage"))  # fmt: skip


def judges(evals: Path | None) -> list[str]:
    """The ``jp1+sha256:`` pins the candidate's signed verdicts name as ``scorer_version``."""
    from opentine._eval_run import read_verdicts
    from opentine._judge_provenance import PREFIX

    if evals is None:
        return []
    try:
        rows = read_verdicts(Path(evals))
    except (OSError, ValueError):
        return []  # the eval gate itself refuses an unreadable folder
    found = {r.get("scorer_version") for r in rows if isinstance(r, dict)}
    pins = {v for v in found if isinstance(v, str) and v.startswith(PREFIX)}
    unpinned = any(isinstance(r, dict) and r.get("scorer") == "llm-judge"
                   and r.get("scorer_version") not in pins for r in rows)  # fmt: skip
    return sorted(pins) + ([UNPINNED] if unpinned else [])


def evaluate(repo_path: Path | None, judge: str, policy: dict[str, Any]) -> tuple[bool, str]:
    """``(ok, detail)`` for *judge* over every queue of the repository."""
    from opentine._label_queue import LabelError
    from opentine._label_report import report, settings

    root = Path(repo_path) / ".tine" / "labels" if repo_path is not None else None
    names = sorted(p.name for p in root.iterdir() if p.is_dir()) if root and root.is_dir() else []
    opts = settings(floor=policy["agreement_floor"], seed=policy.get("seed", 0),
                    resamples=policy.get("resamples"),
                    min_items=policy.get("agreement_min_items"),
                    min_coverage=policy.get("agreement_min_coverage"))  # fmt: skip
    problems = []
    if judge == UNPINNED:
        return False, "an llm-judge verdict names no jp1+sha256: provenance pin"
    for name in names:
        try:
            found = report(repo_path, name, opts, judge_pin=judge)
        except (LabelError, OSError, ValueError) as exc:
            problems.append(f"queue {name} does not verify ({exc})")
            continue
        for row in found["judges"]:
            if row["floor_ok"]:
                return True, f"queue {name}: kappa lower bound {row['cohen']['lower']}"
            problems.append(f"queue {name}: {'; '.join(row['reasons'])}")
    if not problems:
        problems.append("no label queue revealed this judge's outputs")
    return False, f"judge {judge}: " + "; ".join(problems)


def findings(policy: dict[str, Any], repo_path: Path | None,
             evals: Path | None) -> tuple[list, list]:  # fmt: skip
    """``(refusals, advisories)`` for the candidate's judge."""
    from opentine._promote_checks import refusal

    refusals, advisories = [], []
    for judge in judges(evals):
        ok, detail = evaluate(repo_path, judge, policy)
        if ok:
            continue
        if policy.get("judge_agreement") == "required":
            refusals.append(refusal(CODE, detail))
        else:
            advisories.append({"code": f"advisory:{CODE}", "detail": detail})
    return refusals, advisories


__all__ = ["CODE", "MODES", "check_policy", "evaluate", "findings", "judges"]
