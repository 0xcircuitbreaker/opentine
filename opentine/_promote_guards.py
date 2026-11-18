"""Repository guards ``tine promote`` runs before the statistics gate (0.57).

Two refusals tie promotion to the rest of a self-improving agent loop:

- ``promote.key-separation``: the promoting key also holds a scorer, dataset,
  verdict or approver key in the repository's key-role policy
  (``.tine/key-roles.toml``, the same check as ``tine keys lint``). With no
  policy file nothing is refused.
- ``promote.loop-stopped``: ``--loop LOOP`` names a loop with a stop in its
  coord record (``tine loop stop``). A stopped loop's candidates cannot move a
  label; reverting stays allowed. The loop is also read from the candidate
  run's metadata (``opentine.loop``, or an ``opentine.task`` generation), so
  a stopped loop's candidate is refused without ``--loop`` too.
"""

from __future__ import annotations

from pathlib import Path

from opentine._promote_checks import refusal


def key_separation(repo_path: Path | None, signer: str) -> list[dict[str, str]]:
    from opentine._key_roles import KeyRoleError, check_separation
    from opentine.repo import Repo

    if repo_path is None:
        return []
    try:
        store = Repo.open(repo_path).path
    except Exception:  # noqa: BLE001 - no repository, so no key-role policy to apply
        return []
    try:
        check_separation(store, signer)
    except KeyRoleError as exc:
        return [refusal("promote.key-separation", str(exc))]
    return []


def loop_stopped(repo_path: Path | None, loop: str | None,
                 candidate: str | None = None) -> list[dict[str, str]]:  # fmt: skip
    from opentine._promote_pins import run_loops

    if loop and repo_path is None:
        raise ValueError("--loop needs a repository")
    loops = ({loop} if loop else set()) | run_loops(repo_path, candidate or "")
    if not loops:
        return []
    from opentine.coord import _loop_stop
    from opentine.repo import Repo

    repo = Repo.open(repo_path)
    out = []
    for name in sorted(loops):
        state = _loop_stop.loop_state(repo, name)
        if state.get("status") == "stopped":
            out.append(refusal("promote.loop-stopped",
                               f"loop {name} was stopped by {state.get('signer')} "
                               f"({state.get('verification')})"))  # fmt: skip
    return out


def guards(repo_path: Path | None, signer: str, loop: str | None,
           candidate: str | None = None) -> list[dict[str, str]]:  # fmt: skip
    return key_separation(repo_path, signer) + loop_stopped(repo_path, loop, candidate)


__all__ = ["guards", "key_separation", "loop_stopped"]
