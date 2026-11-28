"""Skill labels in ``tine promote`` (0.88): a changed skill tree is shown and labelled.

A lineage variant may name a ``skill`` artifact (its skill tree's digest). When the
candidate's signed lineage record names another skill than the current holder's,
the promotion is a skill change. It is shown in the result and the signed decision
as ``skills`` (``{"from", "to", "label"}``), and it must go through a *skill label*,
one whose name starts with ``skill.``:

``advisory:promote.skill-changed``  the skill changed under a non-skill label, and the
                                    policy does not require skill labels (D12: shown,
                                    never blocking by default);
``promote.skill-label-required``    the same under ``skill_labels = "required"`` (on under
                                    ``profile = "rsi"``);
``promote.skill-unrecorded``        under that rule, a skill label moves to a candidate
                                    whose signed lineage record names no skill.

Under that rule a record counts only when its signer holds a pinned key role
(``REPO/.tine/key-roles.toml`` in an owner-signed trust bundle) and is not an
``optimizer`` key: a record any other key signed, the loop's own included, makes
its run's skill unknown (``conflicting``), so an optimizer cannot forge the skill
digest that decides the label. Outside the rule every signed record counts (D12).

``tine promote --revert`` moves a skill label back like any other label.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MODES = ("advisory", "required")
PREFIX = "skill."
#: Signed records of one run name different skills: always a change, never recorded.
CONFLICT = "conflicting"


def check_policy(policy: dict[str, Any]) -> None:
    """Settle ``skill_labels`` (required under the rsi profile, advisory otherwise)."""
    rsi = policy.get("profile") == "rsi"
    mode = policy.get("skill_labels", "required" if rsi else "advisory")
    if mode not in MODES or (rsi and mode != "required"):
        raise ValueError('skill_labels is "advisory" or "required"; the rsi profile requires it')
    policy["skill_labels"] = mode


def trusted_signers(lineage: Path, repo_path: Path | None) -> set[str]:
    """Pinned non-``optimizer`` keys of the repository, else of the lineage folder's ``.tine``."""
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    stores = [Path(repo_path) / ".tine"] if repo_path is not None else []
    if Path(lineage).name == "lineage" and Path(lineage).parent.name == ".tine":
        stores.append(Path(lineage).parent)
    roles: dict = {}
    for store in stores:  # the repository's pinned roles first, then the lineage's own
        try:
            found = resolve(store)
        except KeyRoleError:
            continue
        if found["status"] == "pinned":
            roles = found["roles"] or {}
            break
    keys = {k for role, held in roles.items() if role != "optimizer" for k in held}
    return keys - set(roles.get("optimizer", []))


def _skills(lineage: Path, trusted: set[str] | None = None) -> dict[str, str | None]:
    """``{mutation run: skill digest or None}`` over the signed variant records.

    With ``trusted``, a record signed by another key makes its run ``CONFLICT``."""
    from opentine import _lineage

    out: dict[str, str | None] = {}
    seen: dict[str, set] = {}
    if not (Path(lineage) / "variants").is_dir():
        return out
    for name, raw in _lineage.read_folder(lineage).items():
        if not name.startswith("variants/"):
            continue
        try:
            doc = _lineage.loads(raw)
        except (ValueError, RecursionError):
            continue
        claim = doc.get("claim") if isinstance(doc, dict) else None
        if not (isinstance(claim, dict) and isinstance(claim.get("artifacts"), dict)
                and _lineage.signed(doc)):  # fmt: skip
            continue
        run, skill = claim.get("mutation_run"), claim["artifacts"].get("skill")
        if isinstance(run, str):
            untrusted = trusted is not None and doc.get("signer") not in trusted
            named = skill if isinstance(skill, str) else None
            seen.setdefault(run, set()).add(CONFLICT if untrusted else named)
    for run, found in seen.items():  # records disagree, or one is untrusted: none decides
        out[run] = next(iter(found)) if len(found) == 1 else CONFLICT
    return out


def findings(policy: dict[str, Any], *, candidate: str, current: str | None, label: str,
             lineage: Path | None,
             repo_path: Path | None) -> tuple[list, list, dict | None]:  # fmt: skip
    """``(refusals, advisories, skills)`` of one promotion."""
    from opentine._promote_checks import refusal

    if lineage is None and repo_path is not None:
        lineage = Path(repo_path) / ".tine" / "lineage"
    required = policy.get("skill_labels") == "required"
    trusted = trusted_signers(Path(lineage), repo_path) if required and lineage else None
    known = _skills(Path(lineage), trusted) if lineage is not None else {}
    to, was = known.get(candidate), known.get(current) if current else None
    skill_label = label.startswith(PREFIX)
    if required and skill_label and to in (None, CONFLICT):
        return [refusal("promote.skill-unrecorded", f"{label} is a skill label and the "
                        "candidate has no lineage record naming one skill, signed by a "
                        "pinned non-optimizer key")], [], None  # fmt: skip
    if to == was and to != CONFLICT:
        return [], [], None
    row = {"from": was, "to": to, "label": label}
    if skill_label:
        return [], [], row
    detail = f"the skill tree changed ({was} -> {to}) under {label}, not a {PREFIX}* label"
    if required:
        return [refusal("promote.skill-label-required", detail)], [], row
    return [], [{"code": "advisory:promote.skill-changed", "detail": detail}], row


def gates(policy: dict[str, Any], repo_path: Path | None, candidate: str, current: str | None,
          label: str, lineage: Path | None,
          folders: dict[str, Path] | None = None) -> tuple[list, list, dict | None]:  # fmt: skip
    """Region pin (0.87), skill label (0.88), judge (0.89), monitor (0.90) findings of promote."""
    from opentine._promote_judges import findings as judges
    from opentine._regions_pin import promote_findings as regions

    held, advised = regions(policy, repo_path)
    more, advice, row = findings(policy, candidate=candidate, current=current, label=label,
                                 lineage=lineage, repo_path=repo_path)  # fmt: skip
    judged, told = judges(policy, repo_path, candidate, lineage, folders or {})
    from opentine._promote_monitors import findings as monitors

    watched, noted = monitors(policy, repo_path, candidate)  # 0.90: monitor coverage
    return held + more + judged + watched, advised + advice + told + noted, row


__all__ = ["MODES", "PREFIX", "check_policy", "findings", "gates", "trusted_signers"]
