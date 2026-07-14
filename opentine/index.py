"""Rebuildable index facade for legacy .tine files."""

from __future__ import annotations

import json
import time
from pathlib import Path

from opentine._canon import FORMAT_VERSION, atomic_write_text
from opentine._index_query import Query, QueryError, _parse_date, match_entry, parse_query
from opentine._index_types import IndexEntry, entry_from_run
from opentine.graph import Run

INDEX_VERSION = 1
INDEX_FILENAME = "index.json"


class RunIndex:
    def __init__(self, runs_dir: str | Path):
        self.runs_dir = Path(runs_dir)
        self.path = self.runs_dir / INDEX_FILENAME
        self.entries: dict[str, IndexEntry] = {}
        self._stale = False

    @classmethod
    def open(cls, runs_dir: str | Path) -> RunIndex:
        index = cls(runs_dir)
        index._load()
        return index

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._stale = True
            return
        if (
            data.get("index_version") != INDEX_VERSION
            or data.get("covered_format_version") != FORMAT_VERSION
        ):
            self.entries = {}
            self._stale = True
            return
        self.entries = {
            name: IndexEntry.from_dict(entry) for name, entry in (data.get("entries") or {}).items()
        }

    def _build_entry(self, file: Path, mtime: float) -> IndexEntry:
        try:
            run = Run.load(file)
        except Exception:
            return IndexEntry(file=file.name, mtime=mtime, unreadable=True)
        return entry_from_run(run, file.name, mtime)

    def sync(self) -> RunIndex:
        if not self.runs_dir.exists():
            self.entries = {}
            return self
        fresh: dict[str, IndexEntry] = {}
        for file in self.runs_dir.glob("*.tine"):
            try:
                mtime = file.stat().st_mtime
            except OSError:
                continue
            existing = self.entries.get(file.name)
            fresh[file.name] = (
                existing
                if existing and not self._stale and existing.mtime == mtime
                else self._build_entry(file, mtime)
            )
        self.entries = fresh
        self._stale = False
        self._save()
        return self

    def reindex(self) -> RunIndex:
        self.entries = {}
        self._stale = True
        return self.sync()

    def update_from_file(self, path: str | Path) -> None:
        file = Path(path)
        try:
            same_directory = file.resolve().parent == self.runs_dir.resolve()
        except OSError:
            same_directory = False
        if not same_directory or not file.exists():
            return
        try:
            mtime = file.stat().st_mtime
        except OSError:
            return
        self.entries[file.name] = self._build_entry(file, mtime)
        self._save()

    def search(self, query: str | Query) -> list[IndexEntry]:
        self.sync()
        parsed = parse_query(query) if isinstance(query, str) else query
        results = [entry for entry in self.entries.values() if match_entry(entry, parsed)]
        results.sort(key=lambda entry: entry.created_at, reverse=True)
        return results

    def lookup(self, run_id: str) -> IndexEntry | None:
        exact = next((entry for entry in self.entries.values() if entry.run_id == run_id), None)
        return exact or next(
            (entry for entry in self.entries.values() if entry.run_id.startswith(run_id)), None
        )

    def _save(self) -> None:
        data = {
            "covered_format_version": FORMAT_VERSION,
            "entries": {name: entry.to_dict() for name, entry in self.entries.items()},
            "generated_at": time.time(),
            "index_version": INDEX_VERSION,
        }
        atomic_write_text(self.path, json.dumps(data, indent=2, sort_keys=True))


__all__ = [
    "IndexEntry",
    "Query",
    "QueryError",
    "RunIndex",
    "_parse_date",
    "entry_from_run",
    "match_entry",
    "parse_query",
]
