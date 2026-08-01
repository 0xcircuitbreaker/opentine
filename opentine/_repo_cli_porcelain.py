"""The two v3 lineage verbs: ``repo-fork`` and ``repo-resume``.

These are the operator twins of the MCP ``fork_run_v3`` and ``resume_run_v3``
tools, and they are the only two v3 verbs whose names collide with a legacy v2
command. ``tine fork`` and ``tine resume`` still branch a ``.tine`` file through
the legacy runs index; ``tine repo-fork`` and ``tine repo-resume`` branch a run
*object* inside a v3 repository. The ``repo-`` prefix exists only for that
collision — ``context``, ``attest``, ``evaluate``, and ``promote`` have no legacy
namesake and so stay unprefixed.

Both verbs make exactly one engine call, ``Repo.fork``, with the same arguments
the matching MCP tool passes, so a CLI-written fork is byte-identical to the
object the tool writes. Three behaviours are mirrored deliberately.

**Resolve, then type-check.** ``resume_run_v3`` runs ``parse_oid(run_id)[0] !=
"run"`` before reading anything, because a resume needs a run's tip list. The CLI
accepts a ref *as well as* an oid, so it resolves first and then applies the same
check — ``tine repo-resume heads/main`` resumes whatever ``heads/main`` names.

**A run with no tip cannot be resumed.** ``tips[-1]`` on an empty list is an
``IndexError``; both surfaces refuse by name instead.

**``overrides={"resume": True}``** is what makes the new run ``status:
"running"`` rather than a plain branch. It is the whole difference between the
two verbs at the engine level.

The one deliberate divergence is the writable namespace.
``mcp_repository._writable_ref`` confines a fork's ``--ref`` to ``experiments/*``
because a fork's ref update is an unconditional overwrite and an MCP client is
acting on run content it just read — untrusted input. An operator at a terminal
already holds the repository, so the CLI validates the ref name and stops there.
``--ref`` is still *required* with no default: a fork that silently advanced
``heads/main`` would be the same accident the MCP confinement exists to prevent.
tests/test_repo_cli_parity.py pins both halves of that divergence.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from opentine._cli_json import emit
from opentine._repo_cli_render import _short_oid
from opentine._repo_cli_write import _receipt, _run_oid
from opentine.repo import Repo
from opentine.repository._refs import normalize_ref

#: A policy override is operator-authored but arrives as an unbounded shell
#: argument and is stored verbatim in a content-addressed blob.
MAX_POLICY_BYTES = 1 << 20


def _target_ref(value: str) -> str:
    """Canonicalize the ``--ref`` a fork will move, before anything is written.

    ``Repo.fork`` normalizes the name itself, but only *after* ``repo.put`` has
    stored the new run, so a malformed ref used to be reported once the object
    already existed. Normalizing here means the refusal precedes the write. The
    MCP boundary calls ``_writable_ref``, which is this plus the ``experiments/``
    namespace test; the CLI deliberately omits the namespace half.
    """
    return normalize_ref(value)


def _policy(raw: str | None) -> dict[str, Any] | None:
    """Parse ``--policy`` into the JSON object ``fork_payload`` stores, or refuse."""
    if raw is None:
        return None
    if len(raw.encode("utf-8", "replace")) > MAX_POLICY_BYTES:
        raise ValueError(f"--policy exceeds the {MAX_POLICY_BYTES}-byte limit")
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"--policy must be valid JSON: {exc}") from None
    if not isinstance(parsed, dict):
        # _overrides refuses a non-object policy too; refusing here names the flag
        # rather than the engine's override vocabulary.
        raise ValueError(f"--policy must be a JSON object, got {type(parsed).__name__}")
    return parsed


def cmd_repo_fork(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    run_id = _run_oid(repo, args.target)
    ref = _target_ref(args.ref)
    # The exact overrides mapping fork_run_v3 builds; None values are dropped by
    # the engine, so an omitted flag and an absent key are the same fork.
    overrides = {"model": args.model, "policy": _policy(args.policy), "prompt": args.prompt}
    forked = repo.fork(run_id, args.from_event, overrides=overrides, ref=ref)
    if getattr(args, "json", False):
        emit(
            {
                "command": "repo-fork",
                "repo": str(repo.path),
                "target": args.target,
                "source_run_id": run_id,
                "from_event": args.from_event,
                "ref": ref,
                "run_id": forked,
                "overrides": {
                    name: value for name, value in overrides.items() if value is not None
                },
                "resumed": False,
            }
        )
        return
    _receipt(
        console, f"Forked {_short_oid(run_id)} at {_short_oid(args.from_event)} -> {ref}", forked
    )


def cmd_repo_resume(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    run_id = _run_oid(repo, args.target)
    ref = _target_ref(args.ref)
    tips = repo.get(run_id).payload().get("tips") or []
    if not tips:
        # tips[-1] on an empty list is an IndexError, which the repo envelope does
        # not catch; both surfaces refuse by name instead.
        raise ValueError(f"cannot resume {args.target}: the run has no event tip")
    resumed = repo.fork(run_id, tips[-1], overrides={"resume": True}, ref=ref)
    if getattr(args, "json", False):
        emit(
            {
                "command": "repo-resume",
                "repo": str(repo.path),
                "target": args.target,
                "source_run_id": run_id,
                "from_event": tips[-1],
                "ref": ref,
                "run_id": resumed,
                "overrides": {"resume": True},
                "resumed": True,
            }
        )
        return
    _receipt(console, f"Resumed {_short_oid(run_id)} at {_short_oid(tips[-1])} -> {ref}", resumed)
