"""``tine promote --require-admission POLICY``: the policy engine wired to the gate (0.75).

Each named policy (a standard name such as ``promote``, a ``./file``, or a
``sha256:`` policy digest) must have admitted the candidate run:
:func:`opentine._policy_record.admitted` finds a held
``opentine.policy-admission/1`` record by a pinned ``policy`` key (never one
that also holds ``optimizer``) that allows it, and none that denies it, among the
records over the run's *current* input: the gate assembles the input document
``tine policy check`` would (the policy's params, overridden by
``--admission-param NAME=VALUE``), takes its digest and counts only admissions
naming that digest. A run denied earlier is admitted by an allow over new
inputs; an allow over inputs that have since changed no longer counts.
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


def _policy_doc(spec: str) -> tuple[str, dict[str, Any] | None]:
    """``(digest, policy)``; a ``sha256:`` spec names a standard policy or none."""
    from opentine import _policy

    if _DIGEST.fullmatch(spec):
        for name in _policy.standard():
            doc = _policy.load(name)[0]
            if _policy.policy_digest(doc) == spec:
                return spec, doc
        return spec, None
    doc = _policy.load(spec)[0]
    return _policy.policy_digest(doc), doc


def _current_input(repo: Any, root: Path, run: str, doc: dict[str, Any] | None,
                   params: list[str]) -> str:  # fmt: skip
    """The digest of the input ``tine policy check`` assembles for *run* now."""
    from opentine import _policy, _policy_input
    from opentine._cli_policy import _params

    document = _policy_input.build(repo, root, run, params=_params(doc or {}, params))
    return _policy.input_digest(document)


def refusals(repo_path: Path | None, candidate: str, specs: list[str],
             params: list[str] | None = None) -> list[dict[str, Any]]:  # fmt: skip
    """``promote.*`` refusals for every named policy that has not admitted *candidate*."""
    from opentine._policy import PolicyFileError
    from opentine._policy_record import admitted
    from opentine.repository.ops import resolve_target

    if not specs:
        return []
    if repo_path is None:
        return [{"code": "promote.admission-policy", "detail": "no repository to read"}]
    from opentine.repo import Repo

    repo = Repo.open(repo_path)
    try:
        run = resolve_target(repo, candidate)
    except Exception as exc:  # noqa: BLE001 - an unresolvable run is never admitted
        return [{"code": "promote.not-admitted", "detail": f"{candidate}: {exc}"}]
    out = []
    for spec in specs:
        try:
            digest, doc = _policy_doc(spec)
            current = _current_input(repo, repo_path, run, doc, list(params or []))
        except (PolicyFileError, ValueError) as exc:
            out.append({"code": "promote.admission-policy", "detail": f"{spec}: {exc}"})
            continue
        if not admitted(repo, run, digest, input_digest=current):
            detail = f"no counting admission by policy {spec} ({digest}) allows {candidate}"
            out.append({"code": "promote.not-admitted", "detail": detail})
    return out


__all__ = ["refusals"]
