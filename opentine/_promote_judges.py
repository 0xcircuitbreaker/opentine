"""Judge assurance in ``tine promote`` (0.89): one gate for every judge a promotion reads.

An eval folder scored by an ``llm-judge`` names its judge in the signed
verdicts' ``scorer_version`` (a ``jp1+sha256:`` pin) and keeps its provenance
beside them (``judge.json``, :mod:`opentine._judge_provenance`). For each judge
of each eval folder the promotion reads, three things are checked:

* **validated**: a held ``opentine.judge-validation/1`` record
  (:mod:`opentine._judge_validation`) signed by a pinned non-optimizer key
  (adversarial cases passed). A ``judge.json`` that is missing, unreadable or
  not what the verdicts pin, and an ``llm-judge`` verdict with no ``jp1`` pin,
  count as unvalidated;
* **agreement**: recomputed now from the repository's label queues
  (``REPO/.tine/labels/*``, :mod:`opentine._label_report`) with the policy's
  ``seed``/``resamples`` -- nothing is taken from a stored report or from the
  validation record. The judge passes when one queue that revealed its signed
  outcomes meets ``agreement_floor`` (both the judge-vs-consensus kappa and
  the multi-rater alpha lower bounds), ``agreement_min_coverage`` and
  ``agreement_min_items``; a queue that does not verify never passes;
* **independent** of the candidate's lineage (:mod:`opentine._judge_lineage`).

``judge_assurance`` in ``[promote]`` decides what a gap does:

``"advisory"`` (default)  ``advisory:judge.unvalidated``,
                          ``advisory:promote.judge-agreement`` and
                          ``advisory:lineage.judge-not-independent``, never
                          blocking (D12);
``"required"``            (on under ``profile = "rsi"``) the same gaps refuse:
                          ``promote.judge-unvalidated``, ``promote.judge-agreement``
                          and ``promote.judge-not-independent`` (fail closed; a
                          candidate no signed lineage record names is not
                          independent).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MODES = ("advisory", "required")
UNPINNED = "llm-judge (no provenance pin)"
ADVISORY = {"unvalidated": "judge.unvalidated", "agreement": "promote.judge-agreement",
            "not-independent": "lineage.judge-not-independent"}  # fmt: skip


def check_policy(policy: dict[str, Any]) -> None:
    """Settle ``judge_assurance`` and the ``agreement_*`` keys (strict decimals)."""
    from opentine._label_report import settings

    rsi = policy.get("profile") == "rsi"
    mode = policy.get("judge_assurance", "required" if rsi else "advisory")
    if mode not in MODES or (rsi and mode != "required"):
        raise ValueError('judge_assurance is "advisory" or "required"; the rsi profile requires it')
    policy["judge_assurance"] = mode
    if isinstance(policy.get("agreement_floor", "0.6"), bool):
        raise ValueError("agreement_floor is a decimal in [0, 1]")
    found = settings(floor=policy.get("agreement_floor"),
                     min_items=policy.get("agreement_min_items"),
                     min_coverage=policy.get("agreement_min_coverage"))  # fmt: skip
    policy["agreement_floor"] = found["floor"]


def _judges(folder: Path) -> tuple[dict[str, Any] | None, list[str]]:
    """``(provenance or None, pins)`` of an eval folder; pins may include :data:`UNPINNED`."""
    from opentine import _json_shallow, _judge_provenance
    from opentine._eval_run import read_verdicts

    try:
        rows = [r for r in read_verdicts(Path(folder)) if isinstance(r, dict)]
    except (OSError, ValueError, AttributeError):
        rows = []  # the eval gate itself refuses an unreadable folder
    found = {r.get("scorer_version") for r in rows}
    pins = sorted(v for v in found if isinstance(v, str) and v.startswith(_judge_provenance.PREFIX))
    if any(r.get("scorer") == "llm-judge" and r.get("scorer_version") not in pins for r in rows):
        pins.append(UNPINNED)
    path = Path(folder) / _judge_provenance.FILE_NAME
    if path.is_file() and not pins:  # a judge.json beside verdicts no judge pin signed
        pins.append(UNPINNED)
    try:
        doc = _json_shallow.loads(path.read_bytes()[: 1 << 20])
        pin = _judge_provenance.pin(doc)
    except (OSError, ValueError, TypeError, RecursionError):
        return None, pins
    return (doc if pins == [pin] else None), pins


def agreement(repo_path: Path | None, judge: str, policy: dict[str, Any]) -> tuple[bool, str]:
    """``(ok, detail)``: *judge*'s agreement recomputed over every queue of the repository."""
    from opentine._label_queue import LabelError
    from opentine._label_report import report, settings

    root = Path(repo_path) / ".tine" / "labels" if repo_path is not None else None
    names = sorted(p.name for p in root.iterdir() if p.is_dir()) if root and root.is_dir() else []
    opts = settings(floor=policy.get("agreement_floor"), seed=policy.get("seed", 0),
                    resamples=policy.get("resamples"),
                    min_items=policy.get("agreement_min_items"),
                    min_coverage=policy.get("agreement_min_coverage"))  # fmt: skip
    problems = []
    for name in names:
        try:
            found = report(repo_path, name, opts, judge_pin=judge)
        except (LabelError, OSError, ValueError) as exc:
            problems.append(f"queue {name} does not verify ({exc})")
            continue
        for row in found["judges"]:
            if row["floor_ok"]:
                return True, f"queue {name}: kappa lower bound {row['judge_vs_consensus']['lower']}"
            problems.append(f"queue {name}: {'; '.join(row['reasons'])}")
    return False, "; ".join(problems or ["no label queue revealed this judge's signed outcomes"])


def _repo(repo_path: Path | None) -> Any:
    from opentine.repo import Repo

    try:
        return Repo.open(repo_path) if repo_path is not None else None
    except (OSError, ValueError):
        return None


def _gaps(policy, repo, repo_path, fam, folder) -> list[tuple[str, str]]:  # noqa: ANN001
    from opentine import _judge_lineage
    from opentine._judge_validation import validated

    doc, pins = _judges(folder)
    gaps = []
    for pin in pins:
        if pin == UNPINNED:
            gaps.append(("unvalidated", "an llm-judge verdict names no jp1+sha256: pin"))
            continue
        if doc is None:
            gaps.append(("unvalidated", "judge.json is missing, unreadable or is not the judge "
                                        "the signed verdicts name"))  # fmt: skip
        elif repo is None or not validated(repo, pin)[0]:
            gaps.append(("unvalidated", f"judge {pin} has no validation record signed by a "
                                        "pinned non-optimizer key"))  # fmt: skip
        ok, detail = agreement(repo_path, pin, policy)
        if not ok:
            gaps.append(("agreement", f"judge {pin}: {detail}"))
        if fam is None or not fam["known"]:  # no lineage is not independence: fail closed
            gaps.append(("not-independent", "no signed lineage record names the candidate, "
                                            "so judge independence is unknown"))  # fmt: skip
        elif doc is not None:
            found = _judge_lineage.check(fam, judges=[{"provenance": doc, "pin": pin}])
            if found["findings"]:
                gaps.append(("not-independent", found["findings"][0]["detail"]))
    return gaps


def findings(policy: dict[str, Any], repo_path: Path | None, candidate: str,
             lineage: Path | None, folders: dict[str, Path]) -> tuple[list, list]:  # fmt: skip
    """``(refusals, advisories)`` for the eval folders a promotion read."""
    from opentine import _judge_lineage
    from opentine._promote_checks import refusal

    required = policy.get("judge_assurance") == "required"
    if lineage is None and repo_path is not None:
        lineage = Path(repo_path) / ".tine" / "lineage"
    fam = _judge_lineage.family(Path(lineage), candidate) if lineage is not None else None
    repo = _repo(repo_path)
    refusals, advisories = [], []
    for side, folder in sorted(folders.items()):
        for kind, detail in _gaps(policy, repo, repo_path, fam, folder):
            text = f"{side} eval: {detail}"
            if required:
                refusals.append(refusal(f"promote.judge-{kind}", text))
            else:
                advisories.append({"code": f"advisory:{ADVISORY[kind]}", "detail": text})
    return refusals, advisories


__all__ = ["MODES", "UNPINNED", "agreement", "check_policy", "findings"]
