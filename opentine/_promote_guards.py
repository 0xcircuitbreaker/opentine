"""Repository guards ``tine promote`` runs before the statistics gate (0.57).

Two refusals tie promotion to the rest of a self-improving agent loop:

- ``promote.key-separation``: the promoting key also holds a scorer, dataset,
  verdict or approver key in the repository's key-role policy
  (``.tine/key-roles.toml``, the same check as ``tine keys lint``). With no
  policy file nothing is refused.
- ``promote.loop-stopped``: ``--loop LOOP`` names a loop with a stop in its
  coord record (``tine loop stop``). A stopped loop's candidates cannot move a
  label; reverting stays allowed.
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


def loop_stopped(repo_path: Path | None, loop: str | None) -> list[dict[str, str]]:
    if not loop:
        return []
    if repo_path is None:
        raise ValueError("--loop needs a repository")
    from opentine.coord import _loop_stop
    from opentine.repo import Repo

    state = _loop_stop.loop_state(Repo.open(repo_path), loop)
    if state.get("status") != "stopped":
        return []
    return [refusal("promote.loop-stopped",
                    f"loop {loop} was stopped by {state.get('signer')} "
                    f"({state.get('verification')})")]  # fmt: skip


def guards(repo_path: Path | None, signer: str, loop: str | None) -> list[dict[str, str]]:
    return key_separation(repo_path, signer) + loop_stopped(repo_path, loop)


__all__ = ["guards", "key_separation", "loop_stopped"]
