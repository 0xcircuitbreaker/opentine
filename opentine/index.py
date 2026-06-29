"""Local run index and query DSL backing ``tine search`` / ``tine ls`` filters.

The index (``.tine_runs/index.json``) is a rebuildable *cache* over the ``.tine``
files in a runs directory — never an authority. The ``.tine`` files remain the
source of truth; a missing, stale, or corrupt index is transparently rebuilt.
Each entry records a per-file ``format_version`` so a mixed v1/v2 store surfaces
both, and the index as a whole records the ``covered_format_version`` it was
built for so a format bump forces a one-time rebuild.
"""

from __future__ import annotations

import json
import shlex
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from opentine._canon import FORMAT_VERSION, atomic_write_text
from opentine.graph import Run, _normalize_tag

INDEX_VERSION = 1
INDEX_FILENAME = "index.json"
PREDICATES = ("tag", "model", "status", "cost", "after", "before")


class QueryError(ValueError):
    """Raised for a malformed search query."""


# --- entries ----------------------------------------------------------------


@dataclass
class IndexEntry:
    file: str
    run_id: str = ""
    model: str = ""
    status: str = ""
    steps: int = 0
    cost: float = 0.0
    created_at: float = 0.0
    mtime: float = 0.0
    format_version: int = 0
    tags: list[str] = field(default_factory=list)
    text: str = ""
    unreadable: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> IndexEntry:
        fields = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in fields})


def _searchable_text(run: Run) -> str:
    """Build a lowercased, redaction-safe free-text blob for a run."""
    data = run.to_dict(redact=True)
    meta = data.get("metadata", {})
    chunks: list[str] = [run.id, run.model_info, run.status.value, *run.tags]
    chunks.append(str(meta.get("user_prompt", "")))
    chunks.append(str(meta.get("system_prompt", "")))
    for step in data.get("graph", {}).get("steps", {}).values():
        inp = step.get("inputs", {})
        if isinstance(inp.get("text"), str):
            chunks.append(inp["text"])
        if isinstance(inp.get("name"), str):
            chunks.append(inp["name"])
        out = step.get("outputs", {})
        if isinstance(out.get("result"), str):
            chunks.append(out["result"])
    return " ".join(c for c in chunks if c)[:8000].lower()


def entry_from_run(run: Run, file: str, mtime: float) -> IndexEntry:
    return IndexEntry(
        file=file,
        run_id=run.id,
        model=run.model_info,
        status=run.status.value,
        steps=len(run.steps),
        cost=run.total_cost,
        created_at=run.created_at,
        mtime=mtime,
        format_version=run.format_version,
        tags=list(run.tags),
        text=_searchable_text(run),
    )


# --- query DSL --------------------------------------------------------------


@dataclass
class Query:
    text: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    model: str | None = None
    status: str | None = None
    cost_min: float | None = None
    cost_max: float | None = None
    after: float | None = None
    before: float | None = None


def _parse_date(value: str) -> float:
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC).timestamp()
        except ValueError:
            continue
    raise QueryError(f"invalid date {value!r}; use YYYY-MM-DD")


def _apply_cost(query: Query, value: str) -> None:
    v = value.strip()
    try:
        if ".." in v:
            lo, _, hi = v.partition("..")
            if lo:
                query.cost_min = float(lo)
            if hi:
                query.cost_max = float(hi)
        elif v.startswith(">="):
            query.cost_min = float(v[2:])
        elif v.startswith(">"):
            query.cost_min = float(v[1:])
        elif v.startswith("<="):
            query.cost_max = float(v[2:])
        elif v.startswith("<"):
            query.cost_max = float(v[1:])
        else:
            query.cost_min = float(v)
    except ValueError as exc:
        raise QueryError(f"invalid cost filter {value!r}") from exc


def parse_query(query: str) -> Query:
    """Parse a query string into a :class:`Query`.

    Tokens of the form ``key:value`` where ``key`` is a known predicate become
    filters; everything else (including URLs like ``http://x`` and stray
    ``foo:bar``) is treated as a free-text AND term. Unbalanced quotes raise
    :class:`QueryError`.
    """
    try:
        tokens = shlex.split(query)
    except ValueError as exc:
        raise QueryError(f"malformed query: {exc}") from exc

    q = Query()
    for token in tokens:
        prefix, sep, value = token.partition(":")
        key = prefix.lower()
        if sep and value and key in PREDICATES:
            if key == "tag":
                norm = _normalize_tag(value)
                if norm:
                    q.tags.append(norm)
            elif key == "model":
                q.model = value.lower()
            elif key == "status":
                q.status = value.lower()
            elif key == "cost":
                _apply_cost(q, value)
            elif key == "after":
                q.after = _parse_date(value)
            elif key == "before":
                q.before = _parse_date(value)
        else:
            q.text.append(token.lower())
    return q


def match_entry(entry: IndexEntry, query: Query) -> bool:
    if entry.unreadable:
        return False
    if query.tags and not all(t in entry.tags for t in query.tags):
        return False
    if query.model and query.model not in entry.model.lower():
        return False
    if query.status and entry.status.lower() != query.status:
        return False
    if query.cost_min is not None and entry.cost < query.cost_min:
        return False
    if query.cost_max is not None and entry.cost > query.cost_max:
        return False
    if query.after is not None and entry.created_at < query.after:
        return False
    if query.before is not None and entry.created_at > query.before:
        return False
    if query.text and not all(term in entry.text for term in query.text):
        return False
    return True


# --- index ------------------------------------------------------------------


class RunIndex:
    def __init__(self, runs_dir: str | Path):
        self.runs_dir = Path(runs_dir)
        self.path = self.runs_dir / INDEX_FILENAME
        self.entries: dict[str, IndexEntry] = {}
        self._stale = False

    @classmethod
    def open(cls, runs_dir: str | Path) -> RunIndex:
        idx = cls(runs_dir)
        idx._load()
        return idx

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
            # schema or format bump -> rebuild everything on the next sync
            self.entries = {}
            self._stale = True
            return
        self.entries = {
            name: IndexEntry.from_dict(e) for name, e in (data.get("entries") or {}).items()
        }

    def _build_entry(self, file: Path, mtime: float) -> IndexEntry:
        try:
            run = Run.load(file)
        except Exception:
            # An unreadable/corrupt/future file must not abort the whole sync.
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
            if existing and not self._stale and existing.mtime == mtime:
                fresh[file.name] = existing
            else:
                fresh[file.name] = self._build_entry(file, mtime)
        self.entries = fresh
        self._stale = False
        self._save()
        return self

    def reindex(self) -> RunIndex:
        self.entries = {}
        self._stale = True
        return self.sync()

    def update_from_file(self, path: str | Path) -> None:
        """Best-effort incremental update for a single file within the runs dir."""
        p = Path(path)
        try:
            same_dir = p.resolve().parent == self.runs_dir.resolve()
        except OSError:
            same_dir = False
        if not same_dir or not p.exists():
            return
        try:
            mtime = p.stat().st_mtime
        except OSError:
            return
        self.entries[p.name] = self._build_entry(p, mtime)
        self._save()

    def search(self, query: str | Query) -> list[IndexEntry]:
        self.sync()
        q = parse_query(query) if isinstance(query, str) else query
        results = [e for e in self.entries.values() if match_entry(e, q)]
        results.sort(key=lambda e: e.created_at, reverse=True)
        return results

    def lookup(self, run_id: str) -> IndexEntry | None:
        for entry in self.entries.values():
            if entry.run_id == run_id:
                return entry
        for entry in self.entries.values():
            if entry.run_id.startswith(run_id):
                return entry
        return None

    def _save(self) -> None:
        data = {
            "index_version": INDEX_VERSION,
            "covered_format_version": FORMAT_VERSION,
            "generated_at": time.time(),
            "entries": {name: entry.to_dict() for name, entry in self.entries.items()},
        }
        atomic_write_text(self.path, json.dumps(data, indent=2, sort_keys=True))
