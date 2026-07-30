"""Rebuildable index facade for legacy .tine files."""

from __future__ import annotations

import json
import stat
import time
from itertools import islice
from pathlib import Path

from opentine._canon import FORMAT_VERSION, atomic_write_text
from opentine._index_query import Query, QueryError, _parse_date, match_entry, parse_query
from opentine._index_types import IndexEntry, entry_from_run
from opentine.graph import Run
from opentine.kernel import validate_json_shape

INDEX_VERSION = 1
INDEX_FILENAME = "index.json"
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_INDEX_RUNS = 1_000
MAX_INDEX_SOURCE_BYTES = 512 * 1024 * 1024
#: Stand-in file name used only to run an extracted entry past the index reader.
_READER_PROBE_NAME = "probe.tine"


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
            with self.path.open("rb") as handle:
                raw = handle.read(MAX_INDEX_BYTES + 1)
            if len(raw) > MAX_INDEX_BYTES:
                raise ValueError("index exceeds its rebuildable size limit")
            validate_json_shape(raw, max_tokens=100_000)
            data = json.loads(raw)
            if not isinstance(data, dict) or not isinstance(data.get("entries", {}), dict):
                raise ValueError("index root and entries must be objects")
            entries = {}
            for name, raw_entry in (data.get("entries") or {}).items():
                if not isinstance(name, str) or not isinstance(raw_entry, dict):
                    raise ValueError("invalid index entry")
                entry = IndexEntry.from_dict(raw_entry)
                if entry.file != name:
                    raise ValueError("index entry key does not match its file")
                entries[name] = entry
        except (
            OSError,
            json.JSONDecodeError,
            UnicodeDecodeError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            self._stale = True
            return
        if (
            data.get("index_version") != INDEX_VERSION
            or data.get("covered_format_version") != FORMAT_VERSION
        ):
            self.entries = {}
            self._stale = True
            return
        self.entries = entries

    def _build_entry(self, file: Path, mtime: float) -> IndexEntry:
        try:
            entry = entry_from_run(Run.load(file), file.name, mtime)
            # Hold this writer to its own reader's rule. from_dict rejects a non-finite
            # cost, but entry_from_run can produce one from per-step-finite billing
            # subtotals whose float sum is inf -- and _save's allow_nan=False then aborts
            # sync() from OUTSIDE this containment, which is the asymmetry all over again.
            #
            # Only what extraction produced is held to that rule. from_dict also applies
            # a path-traversal rule to `file`, which is this directory's own fact and not
            # the artifact's: `save()` writes `<run-id>.tine`, a run id may legally hold a
            # backslash, and the unreadable fallback below records such a name unchecked
            # anyway -- so checking it here only in the success branch would hide from
            # `search` a run this build itself wrote and every previous build found.
            IndexEntry.from_dict({**entry.to_dict(), "file": _READER_PROBE_NAME})
            return entry
        except Exception:
            # Containment covers extraction, not only the read. A run that loads but whose
            # fields cannot be extracted (e.g. per-step-finite billing subtotals that
            # overflow only when summed) marks ONE entry unreadable instead of escaping
            # sync() and blinding ls/search for every healthy run in the directory.
            return IndexEntry(file=file.name, mtime=mtime, unreadable=True)

    def sync(self) -> RunIndex:
        if not self.runs_dir.exists():
            self.entries = {}
            return self
        files = list(islice(self.runs_dir.glob("*.tine"), MAX_INDEX_RUNS + 1))
        if len(files) > MAX_INDEX_RUNS:
            raise ValueError("run index exceeds its artifact-count limit")
        candidates: list[tuple[Path, float]] = []
        total_bytes = 0
        for file in files:
            try:
                info = file.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            total_bytes += info.st_size
            if total_bytes > MAX_INDEX_SOURCE_BYTES:
                raise ValueError("run index exceeds its aggregate source-byte limit")
            candidates.append((file, info.st_mtime))
        fresh: dict[str, IndexEntry] = {}
        for file, mtime in candidates:
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
        exact = [entry for entry in self.entries.values() if entry.run_id == run_id]
        if len(exact) == 1:
            return exact[0]
        matches = [entry for entry in self.entries.values() if entry.run_id.startswith(run_id)]
        return matches[0] if len(matches) == 1 else None

    def _save(self) -> None:
        data = {
            "covered_format_version": FORMAT_VERSION,
            "entries": {name: entry.to_dict() for name, entry in self.entries.items()},
            "generated_at": time.time(),
            "index_version": INDEX_VERSION,
        }
        serialized = json.dumps(data, indent=2, sort_keys=True, allow_nan=False)
        if len(serialized.encode("utf-8")) > MAX_INDEX_BYTES:
            raise ValueError("run index exceeds its serialized size limit")
        atomic_write_text(self.path, serialized)


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
