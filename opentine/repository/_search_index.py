"""The derived FTS5 search index at ``.tine/index/search.sqlite`` (0.44).

Never authoritative: it holds a copy of what the object store already holds --
run prompts and completions, tool names and arguments, file paths named in
those arguments, and run metadata -- so it indexes only what was stored, after
redaction. Delete it and nothing is lost; ``tine repo-search --rebuild-index``
writes it again from the objects. Once it exists, ``Repo.put_run`` and
``Repo.import_pack`` (push, fetch and bundle import) keep it current; if an
incremental update fails the file is deleted, so search falls back to the scan
rather than answering from a stale copy.

Python builds whose sqlite3 lacks FTS5 never create it: search keeps scanning.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import TYPE_CHECKING, Any

from opentine.repository._blob_io import read_verified_blob_prefix

if TYPE_CHECKING:
    from opentine.repository.store import Repo

INDEX_FORMAT = "opentine-search/1"
MAX_INDEX_BLOB_BYTES = 1024 * 1024
MAX_INDEX_TEXT_PER_RUN = 1024 * 1024
MAX_INDEX_EVENTS_PER_RUN = 100_000
_PATH = re.compile(r"(?:[\w.~-]+/)+[\w.-]+|[\w-]+\.[A-Za-z0-9]{1,8}\b")
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, run_id TEXT UNIQUE NOT NULL,"
    " status TEXT NOT NULL, models TEXT NOT NULL, cost REAL NOT NULL,"
    " latency REAL NOT NULL, created_at REAL NOT NULL)",
    "CREATE VIRTUAL TABLE IF NOT EXISTS docs USING fts5(body, tools, paths, meta,"
    " tokenize='unicode61 remove_diacritics 2')",
)
_FTS5: bool | None = None


def fts5_available() -> bool:
    global _FTS5
    if _FTS5 is None:
        try:
            with closing(sqlite3.connect(":memory:")) as probe:
                probe.execute("CREATE VIRTUAL TABLE probe USING fts5(x)")
            _FTS5 = True
        except sqlite3.Error:
            _FTS5 = False
    return _FTS5


def index_path(repo: Repo) -> Path:
    return Path(repo.path) / "index" / "search.sqlite"


def connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=10)
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def _number(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return number if number == number and abs(number) != float("inf") else 0.0


def _text(repo: Repo, oid: Any, budget: list[int]) -> str:
    if not isinstance(oid, str) or budget[0] <= 0 or not repo.has(oid):
        return ""
    limit = min(MAX_INDEX_BLOB_BYTES, budget[0])
    raw, _, _ = read_verified_blob_prefix(repo, oid, prefix_limit=limit, source_limit=limit)
    budget[0] -= len(raw)
    return raw.decode("utf-8", errors="replace")


def extract(repo: Repo, run_id: str) -> tuple[tuple[Any, ...], tuple[str, ...]] | None:
    """``(runs row, docs row)`` for one run object, or None when it is not a run."""
    envelope = repo.get(run_id)
    if envelope.object_type != "run":
        return None
    payload = envelope.payload()
    budget = [MAX_INDEX_TEXT_PER_RUN]
    seen: set[str] = set()
    body = [_text(repo, payload.get(key), budget) for key in ("system_blob", "prompt_blob")]
    tools: list[str] = []
    models: set[str] = set()
    cost = latency = 0.0
    for event_id in list(payload.get("events") or [])[:MAX_INDEX_EVENTS_PER_RUN]:
        try:
            event = repo.get(event_id).payload()
        except (KeyError, OSError, ValueError):
            continue
        if event.get("model"):
            models.add(str(event["model"]))
        cost += _number(event.get("cost"))
        latency += _number(event.get("duration"))
        parts = event.get("input_parts")
        blobs = [event.get("input_blob"), event.get("output_blob")]
        blobs += list(parts.values()) if isinstance(parts, dict) else []
        for oid in blobs:
            if isinstance(oid, str) and oid not in seen:
                seen.add(oid)
                body.append(_text(repo, oid, budget))
        tool = event.get("tool")
        if isinstance(tool, dict) and tool:
            tools.append(json.dumps(tool, sort_keys=True, default=str)[:65536])
    tool_text = "\n".join(tools)
    paths = sorted(set(_PATH.findall(tool_text)))[:4096]
    meta = [run_id, str(payload.get("status", "")), str(payload.get("source_run_id", ""))]
    meta += sorted(models) + [str(payload.get("model") or "")]
    try:
        from opentine.repository._annotations import load_run_annotation

        metadata, tags = load_run_annotation(repo, run_id)
        meta += list(tags) + [json.dumps(metadata, sort_keys=True, default=str)[:65536]]
    except (KeyError, OSError, ValueError, TypeError):
        pass
    row = (run_id, str(payload.get("status", "running")), json.dumps(sorted(models)))
    row += (cost, latency, _number(payload.get("created_at")))
    docs = ("\n".join(part for part in body if part), tool_text, "\n".join(paths))
    return row, (*docs, " ".join(part for part in meta if part))


def _upsert(connection: sqlite3.Connection, repo: Repo, run_ids: list[str]) -> int:
    count = 0
    for run_id in run_ids:
        extracted = extract(repo, run_id)
        if extracted is None:
            continue
        row, docs = extracted
        old = connection.execute("SELECT id FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if old:
            connection.execute("DELETE FROM docs WHERE rowid = ?", old)
            connection.execute("DELETE FROM runs WHERE id = ?", old)
        cursor = connection.execute(
            "INSERT INTO runs(run_id, status, models, cost, latency, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            row,
        )
        connection.execute(
            "INSERT INTO docs(rowid, body, tools, paths, meta) VALUES (?, ?, ?, ?, ?)",
            (cursor.lastrowid, *docs),
        )
        count += 1
    return count


def rebuild(repo: Repo, *, limit: int = 10_000_000) -> int:
    """Write the index afresh from every run object; returns the runs indexed."""
    if not fts5_available():
        raise RuntimeError("this Python's sqlite3 was built without FTS5; search keeps scanning")
    path = index_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(path.name + ".tmp")
    for stale in (staged, Path(f"{staged}-wal"), Path(f"{staged}-shm")):
        stale.unlink(missing_ok=True)
    runs = [oid for oid in repo.iter_oids(limit=limit) if oid.startswith("run:")]
    with closing(sqlite3.connect(staged)) as connection:
        for statement in _SCHEMA:
            connection.execute(statement)
        connection.execute("INSERT INTO meta VALUES ('format', ?)", (INDEX_FORMAT,))
        count = _upsert(connection, repo, runs)
        connection.execute("INSERT INTO docs(docs) VALUES ('optimize')")
        connection.commit()
    for stale in (Path(f"{path}-wal"), Path(f"{path}-shm")):
        stale.unlink(missing_ok=True)
    staged.replace(path)
    return count


def update(repo: Repo, oids: list[str] | tuple[str, ...]) -> None:
    """Index the runs among *oids* when an index exists; drop it if that fails."""
    path = index_path(repo)
    runs = [oid for oid in oids if isinstance(oid, str) and oid.startswith("run:")]
    if not runs or not path.is_file():
        return
    try:
        with closing(connect(path)) as connection, connection:
            _upsert(connection, repo, runs)
    except (sqlite3.Error, KeyError, OSError, ValueError):
        path.unlink(missing_ok=True)  # derived: scanning beats a stale answer
