"""Agent refs, lineage and trust states for ``who`` / ``touched`` / ``audit``.

The action index answers the query; this module re-checks what it claims. Every
trust state comes from a :class:`~opentine._agent_trust.TrustResolver`, which
reloads the run and its manifest, so a forged index row (a planted ``agent_ref``
or ``verified`` column) can neither add a run to ``--verified-only`` nor change
the state shown next to it.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine import _agent_identity as identity
from opentine._actions import Action
from opentine._actions_query import ActionQuery
from opentine._agent_keys import trusted_fingerprints
from opentine._agent_trust import TrustResolver, lineage_refs
from opentine._signing_pins import normalize_pins

MAX_LINEAGE_REFS = 500


def scope_paths(
    args: argparse.Namespace, index: Any = None
) -> tuple[Any, Path | None, Path | None]:
    """``(load_run, manifest dir, agents.toml dir)`` for the command's scope.

    With an action *index*, a legacy run id is looked up in the index's own
    source table (a file in the runs directory), never treated as a path.
    """
    if getattr(args, "repo", None):
        from opentine.repository import Repo
        from opentine.repository._paths import internal_path

        repo = Repo.open(args.repo)
        return repo.load_run, internal_path(repo.path, "actions"), Path(repo.path)
    from opentine._cli_common import _find_run, _runs_dir
    from opentine.graph import Run

    def load(run_id: str) -> Any:
        # Ids reach here from run content (a claimed parent_run): never a path.
        if any(mark in run_id for mark in ("/", "\\", "..")) or run_id.endswith(".tine"):
            raise KeyError(run_id)
        path = _find_run(run_id) if index is None else index.source_file(run_id, _runs_dir())
        if path is None:
            raise KeyError(run_id)
        run = Run.load(path)
        if run.id != run_id:  # a prefix lookup must not stand in for the full id
            raise KeyError(run_id)
        return run

    local = Path(".tine")
    agents = local if local.is_dir() and not local.is_symlink() else None
    return load, _runs_dir() / "manifests", agents


def resolver(args: argparse.Namespace, index: Any = None, **keys: Any) -> TrustResolver:
    load, base, agents = scope_paths(args, index)
    pins = normalize_pins(getattr(args, "pin", None)) | trusted_fingerprints(agents)
    return TrustResolver(load, base, pins=pins, **keys)


def apply_refs(
    args: argparse.Namespace, query: ActionQuery, index: Any, trust: TrustResolver
) -> None:
    """Turn ``--agent-ref`` / ``--lineage`` into exact refs on *query*."""
    refs: list[str] = []
    if ref := getattr(args, "agent_ref", None):
        refs.append(identity.check_query_ref(ref))
    if root := getattr(args, "lineage", None):
        root = identity.check_query_ref(root)
        follow = trust if getattr(args, "verified_only", False) else None
        found = lineage_refs(root, index.edges(), resolver=follow)
        if len(found) > MAX_LINEAGE_REFS:
            raise identity.IdentityError(f"lineage of {root} exceeds {MAX_LINEAGE_REFS} agents")
        refs.extend(sorted(found))
        if ref:  # both: the one ref, and only if it is in the lineage
            refs = [refs[0]] if refs[0] in found else ["\0none"]
    query.agent_refs = list(dict.fromkeys(refs))


def screen(
    actions: list[Action], trust: TrustResolver, *, verified_only: bool, by_ref: bool
) -> list[Action]:
    """With *by_ref*, drop rows whose ref the reloaded run does not hold; with
    *verified_only*, keep only rows from runs whose manifest verifies now."""
    kept = []
    for action in actions:
        if by_ref and not trust.ref_holds(action.run_id, action.agent_ref):
            continue
        if verified_only and not trust.trust(action.run_id).verified:
            continue
        kept.append(action)
    return kept


def states(actions: list[Action], trust: TrustResolver) -> dict[str, str]:
    return {run_id: trust.trust(run_id).state for run_id in {a.run_id for a in actions}}


def add_trust_args(parser: argparse.ArgumentParser, *, filters: bool = True) -> None:
    if filters:
        parser.add_argument("--agent-ref", help="Only this agent (a full agt_ ref or legacy:LABEL)")
        parser.add_argument("--lineage", metavar="REF", help="This agent and its subagents")
        parser.add_argument(
            "--verified-only", action="store_true", help="Only runs with a verified manifest"
        )
    parser.add_argument(
        "--pin",
        action="append",
        metavar="FINGERPRINT",
        help="Treat this Ed25519 key fingerprint as trusted (repeatable)",
    )


__all__ = ["add_trust_args", "apply_refs", "resolver", "scope_paths", "screen", "states"]
