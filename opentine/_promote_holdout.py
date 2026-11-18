"""Promotion refusals for sealed holdouts and canaries (0.61).

``tine promote`` refuses with:

- ``promote.holdout-exposed`` for a sealed holdout over its exposure budget,
  with access records that do not chain, or with a commitment not signed by a
  pinned ``dataset``-role key. The holdouts checked are those named with
  ``--sealed-holdout DIR`` plus every folder under ``REPO/.tine/holdouts/``
  that holds a ``commitment.json``, so leaving the flag out does not skip a
  holdout kept in the repository.
- ``promote.canary-failed`` when ``--canary-lengths FILE`` is given and
  ``tine dataset canary-check`` on it does not pass (a counted canary coded
  below its declared entropy, no counted canary scored, or a lengths file that
  does not parse). Advisory canary findings stay advisory (D12).
"""

from __future__ import annotations

from pathlib import Path

HOLDOUTS = Path(".tine") / "holdouts"


def sealed_folders(named: list[Path], repo: Path | None) -> list[Path]:
    """The named folders, then the repository's own holdouts, each once."""
    found = list(named)
    if repo is not None and (Path(repo) / HOLDOUTS).is_dir():
        found += sorted(p.parent for p in (Path(repo) / HOLDOUTS).glob("*/commitment.json"))
    out: list[Path] = []
    seen: set[str] = set()
    for folder in found:
        key = Path(folder).resolve().as_posix()
        if key not in seen:
            seen.add(key)
            out.append(Path(folder))
    return out


def canary_refusals(lengths: Path | None, repo: Path | None) -> list[dict[str, str]]:
    from opentine._canary import CanaryError
    from opentine._canary_check import check
    from opentine._promote_checks import refusal

    if lengths is None:
        return []
    try:
        row = check(Path(repo or "."), Path(lengths))
    except (CanaryError, OSError, ValueError) as exc:
        return [refusal("promote.canary-failed", f"{Path(lengths).as_posix()}: {exc}")]
    return [refusal("promote.canary-failed", f"{f['code']} {f['canary_sha256']}: {f['detail']}")
            for f in row["findings"] if f["level"] == "fail"]  # fmt: skip


def refusals(named: list[Path], lengths: Path | None, repo: Path | None) -> list[dict[str, str]]:
    from opentine._holdout_access import promote_refusals

    return promote_refusals(sealed_folders(named, repo), repo) + canary_refusals(lengths, repo)


__all__ = ["HOLDOUTS", "canary_refusals", "refusals", "sealed_folders"]
