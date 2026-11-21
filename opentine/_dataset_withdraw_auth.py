"""Who may withdraw a run from curation (0.75).

A withdrawal counts only when its signer is one of:

* the run's **contributor**: the key that signed the run's licence annotation
  (``opentine-dataset/licence/1``, :mod:`opentine._dataset_licence`) held in
  the repository. A repository run object records no signer of its own, so the
  annotation is the run's recorded signer. When annotations on the run name
  more than one key the contributor is ambiguous and none counts (fail closed);
  a pinned curator can still take the run down.
* a pinned ``curator`` key (a maintainer **takedown**), whose reason must be
  one of the withdrawal reason categories. This is also the path for a
  contributor who lost their key.

A pinned ``optimizer`` key never counts, and neither does any other key: an
unpinned third party cannot withdraw someone else's run.
"""

from __future__ import annotations

from typing import Any

CONTRIBUTOR = "contributor"
TAKEDOWN = "curator-takedown"


def contributor(repo: Any, run: str) -> str | None:
    """The one key that signed a valid licence annotation on *run*, else ``None``."""
    from opentine import _containment_records as records
    from opentine._dataset_licence import CONVENTION

    try:
        oids = repo.attestations_for(run)
    except Exception:  # noqa: BLE001 - an unreadable association map names no contributor
        return None
    keys = set()
    for oid in oids:
        row = records.read(repo, oid)
        claim = row["claim"] or {}
        if (row["signed"] and claim.get("convention") == CONVENTION
                and claim.get("contributor") == row["signer"]
                and claim.get("run") == run and row["target"] == run):  # fmt: skip
            keys.add(row["signer"])
    return keys.pop() if len(keys) == 1 else None


def authority(repo: Any, run: str, signer: str, reason: Any) -> tuple[str | None, str]:
    """``(CONTRIBUTOR | TAKEDOWN, "")`` when *signer* may withdraw *run*, else ``(None, why)``."""
    from opentine._dataset_version import _is_optimizer, _roles
    from opentine._dataset_withdraw import REASONS

    if _is_optimizer(repo, signer):
        return None, "the signer is an optimizer key"
    if signer == contributor(repo, run):
        return CONTRIBUTOR, ""
    ok, _ = _roles(repo, signer, ("curator",))
    if ok:
        if reason not in REASONS:
            return None, f"a curator takedown names a reason: {', '.join(REASONS)}"
        return TAKEDOWN, ""
    return None, "the signer is neither the run's contributor nor a pinned curator key"


__all__ = ["CONTRIBUTOR", "TAKEDOWN", "authority", "contributor"]
