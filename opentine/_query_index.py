"""The derived query index at ``.tine/query/index.sqlite`` (0.65).

Derived, rebuildable and never authoritative: every row is read from a
repository object, a lineage record or an eval verdict line and carries its
``oid`` (:mod:`opentine._query_rows`); deleting the file loses nothing and
``tine query index --rebuild`` writes it again. A build is staged next to the
index and moved into place, so a reader never sees half an index.

``meta`` holds ``authority`` (always ``non-authoritative``) and what the index
was built from: ``fingerprint`` (a cheap stat of the object store: the
modification times of its object folders and the names and sizes of its packs),
``objects`` (sha256 of the sorted object ids), ``lineage`` (a digest of the
lineage folder), ``evals`` (the eval folders read and a digest of their
verdict files), ``experiments`` (the same for experiment files, 0.67) and
``elicit`` (a digest of ``.tine/elicit/links``, 0.68). The index is stale
when the lineage, eval, experiment or elicitation digest differs, or
when the fingerprint differs *and* the object ids do (a repack moves objects
without changing them).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterable
from contextlib import closing
from pathlib import Path
from typing import Any

from opentine._query_rows import COLUMNS

FORMAT = "opentine-query-index/1"
AUTHORITY = "non-authoritative"
_INDEXES = (
    "CREATE INDEX steps_oid ON steps (oid)", "CREATE INDEX steps_model ON steps (model)",
    "CREATE INDEX runs_created ON runs (created_at)",
    "CREATE INDEX verdicts_session ON monitor_verdicts (session)",
    "CREATE INDEX decisions_item ON oversight_decisions (item)",
    "CREATE INDEX evals_eval ON evals (eval)", "CREATE INDEX evals_oid ON evals (oid)",
    "CREATE INDEX edges_parent ON lineage_edges (parent)",
    "CREATE INDEX results_oid ON experiment_results (oid)",
    "CREATE INDEX reproductions_manifest ON reproductions (manifest)",
    "CREATE INDEX sabotage_task ON sabotage_tasks (task)",
    "CREATE INDEX elicit_items_oid ON elicit_items (oid)",
    "CREATE INDEX custody_artifact ON weight_custody (artifact)",
)  # fmt: skip
_KEYS = {"runs": "PRIMARY KEY (oid)", "steps": "PRIMARY KEY (run, seq)",
         "monitor_verdicts": "PRIMARY KEY (oid)", "oversight_decisions": "PRIMARY KEY (oid)",
         "lineage_variants": "PRIMARY KEY (variant)", "experiments": "PRIMARY KEY (oid)",
         "experiment_results": "PRIMARY KEY (oid, id)",
         "reproductions": "PRIMARY KEY (oid)", "sabotage_tasks": "PRIMARY KEY (oid)",
         "elicit_links": "PRIMARY KEY (oid)", "elicit_items": "PRIMARY KEY (oid, id)",
         "history_merges": "PRIMARY KEY (oid)", "sandbox_policies": "PRIMARY KEY (oid)",
         "containment_findings": "PRIMARY KEY (oid)",
         "budget_ledger": "PRIMARY KEY (oid)", "weight_custody": "PRIMARY KEY (oid)",
         "organism_records": "PRIMARY KEY (oid)"}  # fmt: skip
VIEWS = (
    "CREATE VIEW costs AS SELECT oid, run, model, provider, cost, input_tokens, output_tokens"
    " FROM steps",
)


def index_path(store: Path) -> Path:
    return Path(store) / "query" / "index.sqlite"


def _schema() -> str:
    tables = []
    for name, columns in COLUMNS.items():
        key = f", {_KEYS[name]}" if name in _KEYS else ""
        tables.append(f"CREATE TABLE {name} ({', '.join(columns)}{key});")
    return "\n".join([*tables, "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"])


def fingerprint(store: Path) -> str:
    """A digest of stat data only: cheap enough to check before every query."""
    lines = []
    objects = Path(store) / "objects"
    for kind in sorted(objects.iterdir()) if objects.is_dir() else []:
        if kind.is_dir():
            lines.append(f"{kind.name} {kind.stat().st_mtime_ns}")
            lines += [f"{kind.name}/{fan.name} {fan.stat().st_mtime_ns}"
                      for fan in sorted(kind.iterdir()) if fan.is_dir()]  # fmt: skip
    packs = Path(store) / "packs"
    for pack in sorted(packs.iterdir()) if packs.is_dir() else []:
        lines.append(f"packs/{pack.name} {pack.stat().st_size}")
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def objects_digest(oids: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(oids)).encode("utf-8")).hexdigest()


def files_digest(files: dict[str, bytes]) -> str:
    lines = [f"{p} {hashlib.sha256(raw).hexdigest()}" for p, raw in sorted(files.items())]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def write(path: Path, chunks: Iterable[dict[str, Iterable[dict[str, Any] | tuple]]],
          meta: dict[str, str]) -> dict[str, int]:  # fmt: skip
    """Write the index at *path* (staged, then moved into place). Row counts per table.

    *chunks* yields ``{table: rows}`` pieces, so a large build streams.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(f"{path.name}.{os.getpid()}.staged")
    for stale in (staged, Path(f"{staged}-journal")):
        stale.unlink(missing_ok=True)
    counts = dict.fromkeys(COLUMNS, 0)
    with closing(sqlite3.connect(staged)) as db:
        db.executescript("PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;" + _schema())
        for chunk in chunks:
            for name, rows in chunk.items():
                _insert(db, name, rows)
        for statement in (*_INDEXES, *VIEWS):
            db.execute(statement)
        for name in COLUMNS:
            counts[name] = db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        full = {"format": FORMAT, "authority": AUTHORITY, **meta,
                "counts": json.dumps(counts, sort_keys=True)}  # fmt: skip
        db.executemany("INSERT INTO meta VALUES (?, ?)", sorted(full.items()))
        db.commit()
    os.replace(staged, path)
    return counts


def _insert(db: sqlite3.Connection, name: str, rows: Iterable[dict[str, Any] | tuple]) -> None:
    columns = COLUMNS[name]
    sql = f"INSERT OR IGNORE INTO {name} VALUES ({', '.join('?' * len(columns))})"
    batch: list[tuple] = []
    for row in rows:
        batch.append(row if isinstance(row, tuple) else tuple(row[c] for c in columns))
        if len(batch) >= 10_000:
            db.executemany(sql, batch)
            batch.clear()
    db.executemany(sql, batch)


def read_meta(path: Path) -> dict[str, str]:
    with closing(sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True)) as db:
        return dict(db.execute("SELECT key, value FROM meta"))


def set_meta(path: Path, key: str, value: str) -> None:
    with closing(sqlite3.connect(path)) as db:
        db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))
        db.commit()


__all__ = ["AUTHORITY", "FORMAT", "VIEWS", "files_digest", "fingerprint", "index_path",
           "objects_digest", "read_meta", "set_meta", "write"]  # fmt: skip
