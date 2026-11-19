"""The derived memory-served index at ``.tine/index/memory-served.sqlite`` (0.61).

Derived, rebuildable and never authoritative: each row comes from a served
step (:mod:`opentine._memory_served`) in a stored run, and deleting the file
loses nothing. ``served(note, run, event)`` holds one row per run that lists a
served event, so a note's consumers are one indexed query, not a walk of the
object store. ``meta.source`` is a digest of every stored run and event id; a
new run or event makes the index stale and the next query rebuilds it. A
rebuild is staged next to the index and moved into place.

:func:`variant_runs` reads a lineage folder (0.58): the runs a variant consumed
are its ``mutation_run`` and the runs its eval verdicts scored, so the
variants affected by a note are the variants whose runs were served it.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

FORMAT = "opentine-memory-served/1"
SCHEMA = """
CREATE TABLE served (note TEXT NOT NULL, run TEXT NOT NULL, event TEXT NOT NULL,
  PRIMARY KEY (note, run, event)) WITHOUT ROWID;
CREATE INDEX served_run ON served (run, note);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def index_path(repo: Any) -> Path:
    from opentine.repository._paths import internal_path

    return internal_path(repo.path, "index") / "memory-served.sqlite"


def _oids(repo: Any) -> tuple[list[str], list[str]]:
    oids = repo.iter_oids()
    return ([o for o in oids if o.startswith("run:")],
            [o for o in oids if o.startswith("event:")])  # fmt: skip


def source_digest(runs: list[str], events: list[str]) -> str:
    text = "\n".join(sorted(runs) + sorted(events))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rows(repo: Any, runs: list[str], events: list[str]) -> list[tuple[str, str, str]]:
    from opentine._memory_served import event_served

    notes: dict[str, list[str]] = {}
    for event in events:
        try:
            found = event_served(repo.get(event).payload())
        except (KeyError, ValueError, OSError):
            continue
        if found:
            notes[event] = found
    if not notes:
        return []
    rows = []
    for run in runs:
        try:
            listed = repo.get(run).payload().get("events") or []
        except (KeyError, ValueError, OSError, AttributeError):
            continue
        for event in listed:
            rows += [(note, run, event) for note in notes.get(event, ())]
    return rows


def rebuild(repo: Any) -> dict[str, int]:
    """Write the index from the object store (staged, then moved into place)."""
    runs, events = _oids(repo)
    path = index_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(f"{path.name}.{os.getpid()}.staged")
    for stale in (staged, Path(f"{staged}-journal")):
        stale.unlink(missing_ok=True)
    rows = _rows(repo, runs, events)
    with closing(sqlite3.connect(staged)) as db:
        db.executescript(SCHEMA)
        db.executemany("INSERT OR IGNORE INTO served VALUES (?, ?, ?)", rows)
        db.executemany("INSERT INTO meta VALUES (?, ?)",
                       [("source", source_digest(runs, events)), ("format", FORMAT)])  # fmt: skip
        db.commit()
    os.replace(staged, path)
    return {"runs": len(runs), "events": len(events), "rows": len(rows)}


def open_index(repo: Any) -> sqlite3.Connection:
    """The index, rebuilt first when missing, unreadable or stale."""
    path = index_path(repo)
    fresh = False
    if path.exists():
        try:
            with closing(sqlite3.connect(path)) as db:
                row = db.execute("SELECT value FROM meta WHERE key = 'source'").fetchone()
            fresh = row is not None and row[0] == source_digest(*_oids(repo))
        except sqlite3.DatabaseError:
            fresh = False
    if not fresh:
        rebuild(repo)
    return sqlite3.connect(path)


def consumers(repo: Any, note: str) -> list[dict[str, str]]:
    """``{run, event}`` for every stored run that lists a step serving *note*."""
    with closing(open_index(repo)) as db:
        found = db.execute("SELECT run, event FROM served WHERE note = ? ORDER BY run, event",
                           (note,)).fetchall()  # fmt: skip
    return [{"run": run, "event": event} for run, event in found]


def variant_runs(
    files: dict[str, bytes], variants: list[str] | None = None
) -> dict[str, list[str]]:
    """``{variant: [run, ...]}``: each variant's mutation run and the runs its verdicts scored."""
    out: dict[str, list[str]] = {}
    for name, raw in sorted(files.items()):
        if not (name.startswith("variants/") and name.endswith(".json")):
            continue
        try:
            claim = json.loads(raw)["claim"]
            variant, runs = claim["variant"], {claim["mutation_run"]}
        except (KeyError, TypeError, ValueError):
            continue
        if variants is not None and variant not in variants:
            continue
        for row in claim.get("evals") or []:
            verdicts = files.get(f"evals/{str(row.get('eval', ''))[7:]}.jsonl", b"")
            for line in verdicts.decode("utf-8", "replace").split("\n"):
                try:
                    runs.add(json.loads(line)["run"])
                except (KeyError, TypeError, ValueError):
                    continue
        out[variant] = sorted(r for r in runs if isinstance(r, str))
    return out


def affected_variants(files: dict[str, bytes], runs: set[str]) -> list[dict[str, Any]]:
    """Variants whose mutation or eval runs are among *runs*, each with the runs it shares."""
    return [{"variant": variant, "runs": sorted(set(used) & runs)}
            for variant, used in variant_runs(files).items() if set(used) & runs]  # fmt: skip


__all__ = ["affected_variants", "consumers", "index_path", "open_index", "rebuild",
           "variant_runs"]  # fmt: skip
