"""Judge assurance in ``tine promote`` (0.89): a judge gates only once it is validated.

An eval folder scored by an ``llm-judge`` keeps its judge provenance beside the
verdicts (``judge.json``, :mod:`opentine._judge_provenance`). For each such
folder the promotion reads, two things are checked:

* the judge has a held ``opentine.judge-validation/1`` record
  (:mod:`opentine._judge_validation`) signed by a pinned non-optimizer key that
  meets the policy's ``judge_floor`` (default 0.6);
* the judge is independent of the candidate's lineage
  (:mod:`opentine._judge_lineage`): its prompt and rubric digests are not
  artifacts of the candidate's family in the lineage folder.

``judge_assurance`` in ``[promote]`` decides what a gap does:

``"advisory"`` (default)  ``advisory:judge.unvalidated`` and
                          ``advisory:lineage.judge-not-independent`` are shown,
                          never blocking (D12);
``"required"``            (on under ``profile = "rsi"``) the same gaps refuse:
                          ``promote.judge-unvalidated`` and
                          ``promote.judge-not-independent``. A ``judge.json`` that
                          is unreadable or does not match the signed verdicts'
                          ``scorer_version`` refuses as unvalidated (fail closed).
"""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Any

MODES = ("advisory", "required")


def check_policy(policy: dict[str, Any]) -> None:
    rsi = policy.get("profile") == "rsi"
    mode = policy.get("judge_assurance", "required" if rsi else "advisory")
    if mode not in MODES or (rsi and mode != "required"):
        raise ValueError('judge_assurance is "advisory" or "required"; the rsi profile requires it')
    policy["judge_assurance"] = mode
    floor = policy.get("judge_floor", "0.6")
    try:
        value = Fraction(str(floor))
    except (ValueError, ZeroDivisionError):
        raise ValueError("judge_floor is a decimal in [0, 1]") from None
    if not 0 <= value <= 1 or isinstance(floor, bool):
        raise ValueError("judge_floor is a decimal in [0, 1]")
    policy["judge_floor"] = str(floor)


def _judge(folder: Path) -> tuple[dict[str, Any] | None, str | None, bool]:
    """``(provenance, pin, present)`` of an eval folder's judge."""
    from opentine import _json_shallow, _judge_provenance
    from opentine._eval_run import read_verdicts

    path = Path(folder) / _judge_provenance.FILE_NAME
    try:
        versions = {str(r.get("scorer_version")) for r in read_verdicts(Path(folder))}
    except (OSError, ValueError, AttributeError):
        versions = set()
    pinned = any(v.startswith(_judge_provenance.PREFIX) for v in versions)
    if not path.is_file():  # a judge-pinned eval without its judge.json is not skipped
        return None, None, pinned
    try:
        doc = _json_shallow.loads(path.read_bytes()[: 1 << 20])
        pin = _judge_provenance.pin(doc)
    except (OSError, ValueError, TypeError, RecursionError):
        return None, None, True
    return (doc, pin, True) if versions == {pin} else (None, None, True)


def findings(policy: dict[str, Any], repo_path: Path | None, candidate: str,
             lineage: Path | None, folders: dict[str, Path]) -> tuple[list, list]:  # fmt: skip
    """``(refusals, advisories)`` for the eval folders a promotion read."""
    from opentine import _judge_lineage
    from opentine._judge_validation import validated
    from opentine._promote_checks import refusal

    required = policy.get("judge_assurance") == "required"
    floor = Fraction(str(policy.get("judge_floor", "0.6")))
    gaps: list[tuple[str, str, str]] = []
    if lineage is None and repo_path is not None:
        lineage = Path(repo_path) / ".tine" / "lineage"
    fam = _judge_lineage.family(Path(lineage), candidate) if lineage is not None else None
    repo = None
    if repo_path is not None:
        from opentine.repo import Repo

        try:
            repo = Repo.open(repo_path)
        except (OSError, ValueError):
            repo = None
    for side, folder in sorted(folders.items()):
        doc, pin, present = _judge(folder)
        if not present:
            continue
        if doc is None:
            gaps.append(("unvalidated", side, "judge.json is unreadable or is not the judge "
                                              "the signed verdicts name"))  # fmt: skip
            continue
        good = validated(repo, pin, "judge", floor)[0] if repo is not None else []
        if not good:
            gaps.append(("unvalidated", side, f"judge {pin} has no validation record signed "
                                              f"by a pinned non-optimizer key at floor "
                                              f"{float(floor):.6f}"))  # fmt: skip
        if fam is not None:
            found = _judge_lineage.check(fam, judges=[{"provenance": doc, "pin": pin}])
            if found["findings"]:
                gaps.append(("not-independent", side, found["findings"][0]["detail"]))
    refusals, advisories = [], []
    for kind, side, detail in gaps:
        text = f"{side} eval: {detail}"
        if required:
            refusals.append(refusal(f"promote.judge-{kind}", text))
        else:
            code = "judge.unvalidated" if kind == "unvalidated" else "lineage.judge-not-independent"
            advisories.append({"code": f"advisory:{code}", "detail": text})
    return refusals, advisories


__all__ = ["MODES", "check_policy", "findings"]
