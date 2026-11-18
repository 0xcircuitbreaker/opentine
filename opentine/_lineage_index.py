"""The derived lineage index at ``LINEAGE_FOLDER/index/lineage.sqlite`` (0.59).

Derived, rebuildable and never authoritative: every row comes from a signed
``opentine.lineage.variant`` record in the lineage folder that ``tine lineage
record`` writes and ``tine lineage check`` reads (:mod:`opentine._lineage`), and
deleting the file loses nothing. A rebuild is staged next to the index and moved into place,
so readers never see a half-built graph.

Tables: ``variants`` (one row per variant id), ``edges`` (child -> parent, both
directions indexed), ``evidence`` (variant -> kind/ref/detail) and ``meta``
(``source``: a digest of every folder file's path and sha256, so any added,
removed or edited record, eval or decision makes the index stale).

When two records claim the same variant id, a record whose signature
verifies beats an unsigned or forged one, then the lowest oid wins; each loser
is counted in ``meta.conflicts`` and kept as a ``conflict`` evidence row on the
variant, so ``why`` shows that the id was contested (a loop cannot squat an id
silently by grinding a low oid). The choice depends on content only, so the
graph hash is the same on every machine.
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

from opentine._lineage import read_folder
from opentine._lineage_claim import folder_rows

SCHEMA = """
CREATE TABLE variants (variant TEXT PRIMARY KEY, oid TEXT NOT NULL, signer TEXT NOT NULL,
  signed INTEGER NOT NULL, loop TEXT NOT NULL);
CREATE TABLE edges (child TEXT NOT NULL, parent TEXT NOT NULL, PRIMARY KEY (child, parent))
  WITHOUT ROWID;
CREATE INDEX edges_parent ON edges (parent, child);
CREATE TABLE evidence (variant TEXT NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL,
  detail TEXT NOT NULL, PRIMARY KEY (variant, kind, ref, detail)) WITHOUT ROWID;
CREATE INDEX evidence_ref ON evidence (ref);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
_NODE_COLUMNS = ("variant", "oid", "signer", "signed", "loop")


def index_path(folder: Any) -> Path:
    return Path(folder) / "index" / "lineage.sqlite"


def source_digest(files: dict[str, bytes]) -> str:
    lines = [f"{p} {hashlib.sha256(raw).hexdigest()}" for p, raw in sorted(files.items())]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def write_index(path: Path, records: Iterable[dict[str, Any]], *, source: str) -> dict[str, int]:
    """Build the index at *path* from *records* (staged, then moved into place)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(f"{path.name}.{os.getpid()}.staged")
    for stale in (staged, Path(f"{staged}-journal")):
        stale.unlink(missing_ok=True)
    chosen: dict[str, dict[str, Any]] = {}
    losers: dict[str, set[str]] = {}
    for row in records:
        held = chosen.get(row["variant"])
        if held is not None:
            keep, lose = sorted((held, row), key=lambda r: (-r["signed"], r["oid"]))
            losers.setdefault(row["variant"], set()).add(lose["oid"])
            row = keep
        chosen[row["variant"]] = row
    conflicts = sum(len(v) for v in losers.values())
    for name, oids in losers.items():
        kept_oid = chosen[name]["oid"]
        extra = [("conflict", oid, kept_oid) for oid in sorted(oids - {kept_oid})]
        chosen[name] = {**chosen[name], "evidence": [*chosen[name]["evidence"], *extra]}
    with closing(sqlite3.connect(staged)) as db:
        db.executescript(SCHEMA)
        db.executemany(
            f"INSERT INTO variants VALUES ({','.join('?' * len(_NODE_COLUMNS))})",
            ([r[c] for c in _NODE_COLUMNS] for r in chosen.values()),
        )
        kept = chosen.values()
        db.executemany("INSERT OR IGNORE INTO edges VALUES (?, ?)",
                       ((r["variant"], p) for r in kept for p in r["parents"]))  # fmt: skip
        db.executemany("INSERT OR IGNORE INTO evidence VALUES (?, ?, ?, ?)",
                       ((r["variant"], *e) for r in kept for e in r["evidence"]))  # fmt: skip
        db.executemany("INSERT INTO meta VALUES (?, ?)",
                       [("source", source), ("conflicts", str(conflicts)),
                        ("format", "opentine-lineage-index/1")])  # fmt: skip
        db.commit()
    os.replace(staged, path)
    return {"variants": len(chosen), "conflicts": conflicts}


def rebuild(folder: Any, files: dict[str, bytes] | None = None) -> dict[str, int]:
    files = read_folder(folder) if files is None else files
    return write_index(index_path(folder), folder_rows(files), source=source_digest(files))


def open_index(folder: Any, *, refresh: bool = True,
               files: dict[str, bytes] | None = None) -> sqlite3.Connection:  # fmt: skip
    """The index, rebuilt first when missing or (with *refresh*) stale."""
    path = index_path(folder)
    if not path.exists():
        rebuild(folder, files)
    elif refresh:
        files = read_folder(folder) if files is None else files
        with closing(sqlite3.connect(path)) as db:
            row = db.execute("SELECT value FROM meta WHERE key = 'source'").fetchone()
        if row is None or row[0] != source_digest(files):
            rebuild(folder, files)
    return sqlite3.connect(path)


def graph(db: sqlite3.Connection, *, loop: str | None = None) -> dict[str, Any]:
    """Nodes, edges and evidence counts, sorted: the ``--format json`` body."""
    where, args = ("WHERE loop = ?", (loop,)) if loop else ("", ())
    nodes = []
    counts = dict(db.execute("SELECT variant, COUNT(*) FROM evidence GROUP BY variant"))
    for values in db.execute(f"SELECT * FROM variants {where} ORDER BY variant", args):
        node = dict(zip(_NODE_COLUMNS, values, strict=True))
        node["signed"] = bool(node["signed"])
        node["evidence"] = counts.get(node["variant"], 0)
        nodes.append(node)
    names = {n["variant"] for n in nodes}
    edges = [{"child": c, "parent": p}
             for c, p in db.execute("SELECT child, parent FROM edges ORDER BY child, parent")
             if c in names]  # fmt: skip
    known = names if loop else {r[0] for r in db.execute("SELECT variant FROM variants")}
    missing = sorted({e["parent"] for e in edges} - known)
    return {"nodes": nodes, "edges": edges, "missing_parents": missing,
            "cyclic": cyclic(edges), "graph_sha256": graph_hash(db)}  # fmt: skip


def cyclic(edges: list[dict[str, str]]) -> list[str]:
    """Variants on or behind a parent cycle (Kahn's algorithm, O(V+E)).

    Content addressing cannot stop two records naming each other as parents,
    because variant ids are names, not digests: a loop can claim a fake cycle
    to make its ancestry unwalkable. ``graph`` reports it rather than hiding it.
    """
    pending: dict[str, int] = {}
    children: dict[str, list[str]] = {}
    for edge in edges:
        pending[edge["child"]] = pending.get(edge["child"], 0) + 1
        pending.setdefault(edge["parent"], 0)
        children.setdefault(edge["parent"], []).append(edge["child"])
    ready = [name for name, count in pending.items() if count == 0]
    while ready:
        for child in children.get(ready.pop(), ()):
            pending[child] -= 1
            if pending[child] == 0:
                ready.append(child)
    return sorted(name for name, count in pending.items() if count > 0)


def graph_hash(db: sqlite3.Connection) -> str:
    """sha256 over every row, in key order: equal for equal graphs, whatever built them."""
    digest = hashlib.sha256()
    for table, order in (("variants", "variant"), ("edges", "child, parent"),
                         ("evidence", "variant, kind, ref, detail")):  # fmt: skip
        for row in db.execute(f"SELECT * FROM {table} ORDER BY {order}"):
            digest.update(json.dumps([table, *row], separators=(",", ":")).encode("utf-8"))
            digest.update(b"\n")
    return digest.hexdigest()


def dot(body: dict[str, Any]) -> str:
    """Graphviz DOT for a :func:`graph` body; ids are JSON-quoted (valid DOT strings)."""
    lines = ["digraph lineage {", "  rankdir=BT;"]
    for node in body["nodes"]:
        label = f"{node['variant'][:19]}\n{node['loop'] or '-'}"
        style = "" if node["signed"] else ", style=dashed"
        lines.append(f"  {json.dumps(node['variant'])} [label={json.dumps(label)}{style}];")
    for edge in body["edges"]:
        lines.append(f"  {json.dumps(edge['child'])} -> {json.dumps(edge['parent'])};")
    lines.append("}")
    return "\n".join(lines) + "\n"


__all__ = ["dot", "graph", "graph_hash", "index_path", "open_index", "rebuild", "write_index"]
