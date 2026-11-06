"""Per-turn workspace snapshots for ``opentine-hook/1`` (0.38).

At each ``turn_end`` the hook stores the agent's working directory as a tree
(:mod:`opentine._snapshot`) and links it from the turn's step, so
``tine rewind RUN@STEP --tree`` restores the workspace as it was after that
turn. Snapshots are on only when the repository's trusted config sets
``hooks.snapshot`` to true, because a snapshot reads
every file under the agent's working directory. A failed snapshot never loses
the step: :mod:`opentine._hook_turns` records the error instead.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine import _hook_turns

TREE_KEY = "opentine.snapshot.tree"


def snapshots_enabled(repo_path: Path) -> bool:
    from opentine import _porcelain_config as porcelain

    value = porcelain.effective(repo_path).get("hooks.snapshot", "")
    return str(value).lower() in ("1", "true", "yes", "on")


@_hook_turns.register
def snapshot_turn(context: _hook_turns.TurnContext) -> dict[str, Any] | None:
    if not context.cwd or not snapshots_enabled(Path(context.repo.path)):
        return None
    from opentine._snapshot import snapshot

    taken = snapshot(context.repo, context.cwd)
    return {TREE_KEY: taken.oid, "opentine.snapshot.files": taken.files}


__all__ = ["TREE_KEY", "snapshot_turn", "snapshots_enabled"]
