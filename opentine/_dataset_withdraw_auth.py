"""Who may withdraw a run from curation (0.75).

A withdrawal counts only when its signer is one of:

* the run's **contributor**: the key that signed the run's licence annotation
  (``opentine-dataset/licence/1``, :mod:`opentine._dataset_licence`) held in
  the repository, when that key is also pinned in the ``runner`` role of the
  owner-signed key-role policy. A repository run object records no signer of
  its own, and anyone can store an annotation, so only a pinned key can be a
  run's contributor: a stranger who annotates a run first gains nothing. When
  pinned annotations name more than one key, a new withdrawal is refused (fail
  closed); a pinned curator can still take the run down.
* a pinned ``curator`` key (a maintainer **takedown**), whose reason must be
  one of the withdrawal reason categories. This is also the path for a
  contributor who lost their key.

A pinned ``optimizer`` key never counts, and neither does any other key: an
unpinned third party cannot withdraw someone else's run.

A withdrawal already signed by a contributor key stays in force when another
key annotates the run later (:func:`authority` with ``signed=True``): the
uniqueness test applies only when a withdrawal is signed.
"""

from __future__ import annotations

from typing import Any

CONTRIBUTOR = "contributor"
TAKEDOWN = "curator-takedown"


def contributors(repo: Any, run: str) -> set[str]:
    """The pinned ``runner`` keys that signed a valid licence annotation on *run*."""
    from opentine import _containment_records as records
    from opentine._dataset_licence import CONVENTION

    try:
        oids = repo.attestations_for(run)
    except Exception:  # noqa: BLE001 - an unreadable association map names no contributor
        return set()
    keys = set()
    for oid in oids:
        row = records.read(repo, oid)
        claim = row["claim"] or {}
        if (row["signed"] and claim.get("convention") == CONVENTION
                and claim.get("contributor") == row["signer"]
                and claim.get("run") == run and row["target"] == run):  # fmt: skip
            keys.add(row["signer"])
    from opentine._dataset_version import _roles

    return {k for k in keys if _roles(repo, k, ("runner",))[0]}


def contributor(repo: Any, run: str) -> str | None:
    """The one pinned key that signed a valid licence annotation on *run*, else ``None``."""
    keys = contributors(repo, run)
    return next(iter(keys)) if len(keys) == 1 else None


def authority(
    repo: Any, run: str, signer: str, reason: Any, *, signed: bool = False
) -> tuple[str | None, str]:
    """``(CONTRIBUTOR | TAKEDOWN, "")`` when *signer* may withdraw *run*, else ``(None, why)``.

    *signed* is for a withdrawal already held: its signer need only be one of
    the run's contributor keys, so a later annotation cannot cancel it.
    """
    from opentine._dataset_version import _is_optimizer, _roles
    from opentine._dataset_withdraw import REASONS

    if _is_optimizer(repo, signer):
        return None, "the signer is an optimizer key"
    if (signer in contributors(repo, run)) if signed else (signer == contributor(repo, run)):
        return CONTRIBUTOR, ""
    ok, _ = _roles(repo, signer, ("curator",))
    if ok:
        if reason not in REASONS:
            return None, f"a curator takedown names a reason: {', '.join(REASONS)}"
        return TAKEDOWN, ""
    return None, "the signer is neither the run's contributor nor a pinned curator key"


__all__ = ["CONTRIBUTOR", "TAKEDOWN", "authority", "contributor", "contributors"]
