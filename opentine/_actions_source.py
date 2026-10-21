"""Where the action index reads runs from, and where it keeps itself.

* a legacy runs directory (``.tine_runs``): every ``*.tine`` file, stamped by
  size and modification time, with the same artifact-count and byte caps as
  the run index; the index lives beside them as ``actions.sqlite``;
* a v3 repository: the run each ref points at (what ``repo-log`` shows), keyed
  by object id -- immutable, so a run is indexed once; the index lives at
  ``.tine/indexes/actions.sqlite``.
"""

from __future__ import annotations

import stat
from collections.abc import Iterator
from itertools import islice
from pathlib import Path
from typing import Any

from opentine._actions_db import ActionIndex, Source, SyncReport
from opentine.graph import Run
from opentine.index import MAX_INDEX_RUNS, MAX_INDEX_SOURCE_BYTES

INDEX_NAME = "actions.sqlite"
MAX_REPO_RUNS = 10_000


def runs_dir_sources(runs_dir: Path) -> Iterator[Source]:
    files = sorted(islice(runs_dir.glob("*.tine"), MAX_INDEX_RUNS + 1))
    if len(files) > MAX_INDEX_RUNS:
        raise ValueError("action index exceeds the run-index artifact-count limit")
    total = 0
    for file in files:
        try:
            info = file.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        total += info.st_size
        if total > MAX_INDEX_SOURCE_BYTES:
            raise ValueError("action index exceeds the run-index aggregate source-byte limit")
        yield Source(
            key=file.name,
            stamp=f"{info.st_size}:{info.st_mtime_ns}",
            load=lambda path=file: Run.load(path),
        )


def repo_sources(repo: Any) -> Iterator[Source]:
    seen: set[str] = set()
    for _name, oid in sorted(repo.list_refs().items()):
        if not isinstance(oid, str) or not oid.startswith("run:") or oid in seen:
            continue
        seen.add(oid)
        if len(seen) > MAX_REPO_RUNS:
            raise ValueError("action index exceeds its repository run limit")
        yield Source(key=oid, stamp=oid, load=lambda target=oid: repo.load_run(target))


def open_runs_dir(runs_dir: Path, *, fresh: bool = False) -> tuple[ActionIndex, SyncReport]:
    """The runs directory's action index; *fresh* builds it in memory from the runs."""
    runs_dir.mkdir(parents=True, exist_ok=True)
    index = ActionIndex(":memory:" if fresh else runs_dir / INDEX_NAME)
    return index, index.sync(runs_dir_sources(runs_dir))


def open_repo(repo: Any, *, fresh: bool = False) -> tuple[ActionIndex, SyncReport]:
    """The repository's action index; *fresh* builds it in memory from the objects."""
    from opentine.repository._paths import internal_path

    if fresh:
        index = ActionIndex(":memory:")
        return index, index.sync(repo_sources(repo))
    directory = internal_path(repo.path, "indexes")
    directory.mkdir(parents=True, exist_ok=True)
    index = ActionIndex(internal_path(repo.path, "indexes", INDEX_NAME))
    return index, index.sync(repo_sources(repo))


__all__ = ["INDEX_NAME", "open_repo", "open_runs_dir", "repo_sources", "runs_dir_sources"]
