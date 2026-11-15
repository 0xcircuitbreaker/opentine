"""Stage, commit and recover an all-or-nothing tenant import (0.52, ``_tenant_import_http``).

An import is staged under ``<objects root>/.imports/<tenant>/<token>/``: every
Review and project version is written there with the stores' own writers, then
``journal.json`` (the refs to create, the Review ids, the project versions) is
written last. Commit moves each staged Review directory and project version
into place (never over an existing one), then creates every ref in **one**
index transaction (``update_refs``, expected ``null``) -- the commit point --
and finally marks the staging ``committed`` and removes it. If the ref
transaction is refused, the moves are undone.

:func:`recover` makes any staging left by an error or a crash whole again: no
journal means nothing was visible, so it is discarded; a journal whose refs
already exist (or which is marked committed) is rolled forward; any other is
rolled back. It runs before every import of the tenant. So the tenant ends
either unchanged or fully imported.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine.kernel import canonical_json
from opentine.remote import _project_store, _review_store
from opentine.remote.backend import valid_tenant

IMPORTS = ".imports"
JOURNAL = "journal.json"
COMMITTED = "committed"
#: Test hook: called with a step name before every write; raising injects a fault.
FAULT: Callable[[str], None] | None = None


def _step(name: str) -> None:
    if FAULT is not None:
        FAULT(name)


def _area(root: Path, tenant: str) -> Path:
    return Path(root) / IMPORTS / valid_tenant(tenant)


def stage(root: Path, tenant: str, plan: Any) -> Path:
    """Write *plan*'s Reviews and project versions under a fresh staging folder."""
    base = _area(root, tenant) / uuid.uuid4().hex
    base.mkdir(parents=True)
    for _review_id, versions, decisions in plan.reviews:
        for version in versions:
            _step("stage")
            _review_store.append(base, tenant, version)
        for decision in decisions:
            _step("stage")
            _review_store.decide(base, tenant, decision)
    for manifest in plan.project:
        _step("stage")
        _project_store.append(base, tenant, manifest)
    journal = {"refs": [list(row) for row in plan.rows],
               "reviews": [row[0] for row in plan.reviews],
               "project": [int(m["seq"]) for m in plan.project]}  # fmt: skip
    _step("journal")
    temporary = base / (JOURNAL + ".tmp")
    temporary.write_bytes(canonical_json(journal))
    os.replace(temporary, base / JOURNAL)
    return base


def _moves(root: Path, base: Path, tenant: str, journal: dict) -> list[tuple[Path, Path]]:
    moves = [(_review_store._dir(base, tenant, rid), _review_store._dir(root, tenant, rid))
             for rid in journal["reviews"]]  # fmt: skip
    moves += [(_project_store._path(base, tenant, seq), _project_store._path(root, tenant, seq))
              for seq in journal["project"]]  # fmt: skip
    return moves


def _place(moves: list[tuple[Path, Path]]) -> bool:
    """Move each staged item into place; ``False`` if a target appeared meanwhile."""
    for source, target in moves:
        if source.exists() and not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            _step("place")
            os.rename(source, target)
    return all(target.exists() and not source.exists() for source, target in moves)


def _unplace(moves: list[tuple[Path, Path]]) -> None:
    for source, target in reversed(moves):
        if target.exists() and not source.exists():
            _step("unplace")
            os.rename(target, source)


def _discard(base: Path) -> None:
    _step("discard")
    shutil.rmtree(base)


def _journal(base: Path) -> dict[str, Any] | None:
    try:
        return json.loads((base / JOURNAL).read_bytes())
    except FileNotFoundError:
        return None


def _committed(index: Any, tenant: str, base: Path, journal: dict) -> bool:
    if (base / COMMITTED).exists():
        return True
    rows = journal["refs"]
    current = index.list_refs(tenant) if rows else {}
    return bool(rows) and all(current.get(name) == new for name, new in rows)


def commit(index: Any, root: Path, tenant: str, base: Path) -> bool:
    """Make a staged import visible; ``False`` (and nothing visible) on a conflict."""
    journal = _journal(base) or {}
    moves = _moves(root, base, tenant, journal)
    placed = _place(moves)
    rows = journal["refs"]
    if placed and rows:
        _step("refs")
        placed = index.update_refs(tenant, [(name, new, None) for name, new in rows])
    if not placed:
        _unplace(moves)
        _discard(base)
        return False
    _step("committed")
    (base / COMMITTED).write_bytes(b"")
    _discard(base)
    return True


def recover(index: Any, root: Path, tenant: str) -> list[str]:
    """Roll every leftover staging of *tenant* forward or back; return what was done."""
    area = _area(root, tenant)
    done: list[str] = []
    for base in sorted(area.iterdir()) if area.is_dir() else []:
        journal = _journal(base)
        if journal is None:
            done.append("discarded")
        elif _committed(index, tenant, base, journal):
            _place(_moves(root, base, tenant, journal))
            done.append("rolled-forward")
        else:
            _unplace(_moves(root, base, tenant, journal))
            done.append("rolled-back")
        _discard(base)
    return done


__all__ = ["FAULT", "IMPORTS", "commit", "recover", "stage"]
