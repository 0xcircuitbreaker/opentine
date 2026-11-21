"""``tine promote --require-admission POLICY``: the policy engine wired to the gate (0.75).

Each named policy (a standard name such as ``promote``, a ``./file``, or a
``sha256:`` policy digest) must have admitted the candidate run:
:func:`opentine._policy_record.admitted` finds a held
``opentine.policy-admission/1`` record by a pinned ``policy`` key (never one
that also holds ``optimizer``) that allows it, and none that denies it.
Otherwise the promotion is refused ``promote.not-admitted``; a policy that
cannot be read is refused ``promote.admission-policy`` (fails closed). The check
runs before the label can move. Advisory rules never decide an admission (D12),
so they never block here either.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _digest(spec: str) -> str:
    from opentine import _policy

    if _DIGEST.fullmatch(spec):
        return spec
    return _policy.policy_digest(_policy.load(spec)[0])


def refusals(repo_path: Path | None, candidate: str, specs: list[str]) -> list[dict[str, Any]]:
    """``promote.*`` refusals for every named policy that has not admitted *candidate*."""
    from opentine._policy import PolicyFileError
    from opentine._policy_record import admitted

    if not specs:
        return []
    if repo_path is None:
        return [{"code": "promote.admission-policy", "detail": "no repository to read"}]
    from opentine.repo import Repo

    repo = Repo.open(repo_path)
    out = []
    for spec in specs:
        try:
            digest = _digest(spec)
        except (PolicyFileError, ValueError) as exc:
            out.append({"code": "promote.admission-policy", "detail": f"{spec}: {exc}"})
            continue
        if not admitted(repo, candidate, digest):
            detail = f"no counting admission by policy {spec} ({digest}) allows {candidate}"
            out.append({"code": "promote.not-admitted", "detail": detail})
    return out


__all__ = ["refusals"]
