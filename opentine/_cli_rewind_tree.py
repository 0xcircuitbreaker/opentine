"""``tine rewind --tree``: restore a workspace snapshot (a tree blob) exactly.

The target is a tree id (``blob:sha256:...``), or ``RUN[@STEP]`` with
``--tree`` to use the snapshot linked from that step (``outputs.tree``, or the
nearest earlier step that has one). Dry run by default; ``--apply`` writes.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, NoReturn

from opentine._cli_errors import fail
from opentine._cli_who_render import emit_or_print
from opentine.kernel import OID_RE, KernelError


def _fail(message: str) -> NoReturn:
    fail(message, 2)


def is_tree_target(target: str) -> bool:
    match = OID_RE.fullmatch(target)
    return bool(match and match.group(1) == "blob")


def step_tree(run: Any, until: int) -> str | None:
    """The tree linked from step *until* (or the nearest earlier step)."""
    steps = run.steps[: until + 1] if until >= 0 else run.steps
    for step in reversed(steps):
        outputs = step.outputs if isinstance(step.outputs, dict) else {}
        if isinstance(outputs.get("tree"), str) and is_tree_target(outputs["tree"]):
            return outputs["tree"]
    return None


def rewind_tree(args: argparse.Namespace, tree_oid: str, extra: dict[str, Any]) -> None:
    from opentine._rewind import RewindError
    from opentine._rewind_tree import apply_tree, plan_tree
    from opentine.repository import Repo

    root = Path(args.root or ".").resolve()
    try:
        repo = Repo.open(getattr(args, "repo", None) or root)
        plan = plan_tree(repo, tree_oid, root, allow_control=args.allow_control_dirs)
    except (KernelError, KeyError, OSError, ValueError) as exc:
        _fail(f"Cannot read tree {tree_oid}: {exc}")
    applied = bool(args.apply)
    if applied:
        try:
            apply_tree(repo, plan, root)
        except (RewindError, OSError) as exc:
            _fail(f"Stopped writing: {exc}")
    payload = {
        **extra,
        "tree": tree_oid,
        "root": root.as_posix(),
        "dry_run": not args.apply,
        "applied": applied,
        "restore": [{"path": path, "mode": mode} for path, mode, _ in plan.writes],
        "remove": plan.removes,
        "unchanged": plan.unchanged,
        "refused": [{"path": path, "reason": why} for path, why in plan.refused],
        "kept": plan.kept,
    }
    emit_or_print(args, "rewind", payload, lambda: _human(payload))


def _human(payload: dict[str, Any]) -> None:
    from opentine._cli_common import _terminal, console

    verb = "Restored" if payload["applied"] else "Would restore"
    gone = "Removed" if payload["applied"] else "Would remove"
    for row in payload["restore"]:
        console.print(f"{verb}: {_terminal(row['path'])}")
    for path in payload["remove"]:
        console.print(f"{gone}: {_terminal(path)}")
    for row in payload["refused"]:
        console.print(f"Refused: {_terminal(row['path'])}  ({_terminal(row['reason'])})")
    if not payload["restore"] and not payload["remove"]:
        console.print("Working tree already matches the snapshot.")
    elif not payload["applied"]:
        console.print("Dry run; pass --apply to write.")


__all__ = ["is_tree_target", "rewind_tree", "step_tree"]
