"""Which runs a git link can name, and how to load one by that name.

Inside a v3 repository a run is named by its object id (``run:sha256:...``):
stable, content-addressed and what ``repo-show`` takes. In a legacy runs
directory it is named by its run id. The action index keys its sources the
same way (object id, or file name), and :class:`RunCatalog` maps between the
two so a trailer written from one is found again from the other.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opentine._actions_db import ActionIndex, SyncReport
from opentine._actions_source import open_repo, open_runs_dir
from opentine.graph import Run


@dataclass
class RunCatalog:
    """Run names for one action index scope (a repository or a runs directory)."""

    index: ActionIndex
    report: SyncReport
    repo: Any = None
    runs_dir: Path | None = None
    by_run_id: dict[str, str] = field(default_factory=dict)  # run id -> source key
    by_source: dict[str, str] = field(default_factory=dict)  # source key -> run id

    def __post_init__(self) -> None:
        for source, run_id in self.index.db.execute("SELECT source, run_id FROM sources"):
            if run_id:
                self.by_run_id.setdefault(run_id, source)
                self.by_source[source] = run_id

    def canonical(self, run_id: str) -> str:
        """The name a link records: the object id in a repository, else the run id."""
        return self.by_run_id.get(run_id, run_id) if self.repo is not None else run_id

    def run_id(self, name: str) -> str:
        """The run id actions carry, for a name a link recorded."""
        return self.by_source.get(name, name)

    def known(self, name: str) -> bool:
        return name in self.by_source or name in self.by_run_id

    def load(self, name: str) -> Run:
        """The run a link or an action names; raises when it is not held here."""
        if self.repo is not None:
            oid = name if name in self.by_source else self.by_run_id.get(name, name)
            return self.repo.load_run(oid)
        source = self.by_run_id.get(name)
        if source is None or self.runs_dir is None:
            raise KeyError(name)
        return Run.load(self.runs_dir / source)

    def names(self) -> Iterator[str]:
        yield from (self.canonical(run_id) for run_id in self.by_run_id)


def open_catalog(repo_path: str | None, runs_dir: Path, *, fresh: bool = False) -> RunCatalog:
    """The catalog for ``--repo PATH``, or for the legacy runs directory."""
    if repo_path:
        from opentine.repository import Repo

        repo = Repo.open(repo_path)
        index, report = open_repo(repo, fresh=fresh)
        return RunCatalog(index, report, repo=repo)
    index, report = open_runs_dir(runs_dir, fresh=fresh)
    return RunCatalog(index, report, runs_dir=runs_dir)


def run_summary(catalog: RunCatalog, name: str) -> dict[str, Any]:
    """Model, cost and status of a linked run, or ``found: False``."""
    try:
        run = catalog.load(name)
    except Exception:  # noqa: BLE001 - a link to a run not held here is still reported
        return {"run": name, "found": False}
    models = sorted({step.model_info for step in run.steps if step.model_info})
    return {
        "run": name,
        "found": True,
        "model": run.model_info or (models[0] if models else ""),
        "cost": round(float(run.total_cost), 6),
        "status": str(run.status),
        "steps": len(run.steps),
    }


__all__ = ["RunCatalog", "open_catalog", "run_summary"]
