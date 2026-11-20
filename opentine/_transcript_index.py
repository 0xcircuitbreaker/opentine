"""The transcript index at ``.tine/transcripts/index.sqlite`` (0.74, release 0.73.0).

Derived, rebuildable and never authoritative, like the query index: one row
per ``run`` object (its oid, step count, transcript size, whether a cap cut
it, the sha256 of the transcript text, the vector and its LSH keys). Deleting
the file loses nothing. A build is staged next to the index and moved into
place; runs already in an index built with the same configuration keep their
vectors, so a rebuild embeds only new runs.

``meta`` records ``format``, ``authority`` (``non-authoritative``), the
``backend`` description and ``backend_digest``, the ``caps``, the ``ann``
parameters and ``runs`` (sha256 of the sorted run oids). The index is stale
when any of these differ from what a build now would use.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from opentine import _transcript_ann as ann
from opentine import _transcript_embed as te
from opentine._transcript_text import Caps, reader, transcript

FORMAT = "opentine-transcript-index/1"
AUTHORITY = "non-authoritative"
PARALLEL_FROM = 5000
_CHUNK = 1000
_SCHEMA = (
    "CREATE TABLE transcripts (run TEXT PRIMARY KEY, steps INTEGER NOT NULL,"
    " bytes INTEGER NOT NULL, truncated INTEGER NOT NULL, text_sha256 TEXT NOT NULL,"
    " vector BLOB NOT NULL, keys TEXT NOT NULL);"
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
)


def index_path(store: Path) -> Path:
    return Path(store) / "transcripts" / "index.sqlite"


def run_oids(repo: Any) -> list[str]:
    return sorted(o for o in repo.iter_oids() if o.startswith("run:"))


def runs_digest(oids: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(oids)).encode("utf-8")).hexdigest()


def config(backend: Any, caps: Caps) -> dict[str, str]:
    return {"format": FORMAT, "authority": AUTHORITY,
            "backend": json.dumps(backend.description(), sort_keys=True),
            "backend_digest": te.backend_digest(backend),
            "caps": json.dumps(caps.as_dict(), sort_keys=True),
            "ann": json.dumps(ann.describe(), sort_keys=True)}  # fmt: skip


def embed_rows(repo: Any, oids: list[str], backend: Any, caps: Caps) -> list[tuple]:
    read = reader(repo)
    return text_rows([transcript(repo, oid, caps, read) for oid in oids], backend)


def text_rows(docs: list[Any], backend: Any) -> list[tuple]:
    """Index rows for :class:`~opentine._transcript_text.Transcript` values."""
    vectors = backend.embed([d.text for d in docs])
    out = []
    for doc, vector in zip(docs, vectors, strict=True):
        raw = doc.text.encode("utf-8")
        out.append((doc.run, doc.steps, len(raw), int(doc.truncated),
                    hashlib.sha256(raw).hexdigest(), ann.pack(vector),
                    " ".join(map(str, ann.keys(vector)))))  # fmt: skip
    return out


def _chunk_job(project: str, oids: list[str], caps: tuple[int, int]) -> list[tuple]:
    from opentine.repository import Repo

    return embed_rows(Repo.open(project), oids, te.HashBackend(), Caps(*caps))


def _embed_all(repo: Any, oids: list[str], backend: Any, caps: Caps, workers: int | None):
    pieces = [oids[i : i + _CHUNK] for i in range(0, len(oids), _CHUNK)]
    if workers is None:
        workers = min(os.cpu_count() or 1, 8) if len(oids) >= PARALLEL_FROM else 1
    if workers <= 1 or not isinstance(backend, te.HashBackend):
        yield from (embed_rows(repo, piece, backend, caps) for piece in pieces)
        return
    from concurrent.futures import ProcessPoolExecutor

    project = Path(repo.path).parent.as_posix()
    shape = (caps.step_bytes, caps.max_bytes)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        yield from pool.map(_chunk_job, [project] * len(pieces), pieces, [shape] * len(pieces))


def _reusable(path: Path, wanted: dict[str, str]) -> dict[str, tuple]:
    if not path.is_file():
        return {}
    try:
        with closing(sqlite3.connect(path)) as db:
            meta = dict(db.execute("SELECT key, value FROM meta"))
            if any(meta.get(k) != wanted[k] for k in ("format", "backend_digest", "caps", "ann")):
                return {}
            return {row[0]: row for row in db.execute("SELECT * FROM transcripts")}
    except sqlite3.DatabaseError:
        return {}


def build(repo: Any, backend: Any = None, caps: Caps = Caps(), *,
          workers: int | None = None, reuse: bool = True) -> dict[str, Any]:  # fmt: skip
    """Write the index; ``{"path", "runs", "embedded", "reused", "truncated"}``.

    With ``reuse`` (an incremental refresh) rows of an index built with the same
    configuration are kept; the index file is writable, so ``reuse=False`` (a
    rebuild) embeds every run from the objects again.
    """
    backend = backend or te.HashBackend()
    path = index_path(Path(repo.path))
    oids = run_oids(repo)
    meta = {**config(backend, caps), "runs": runs_digest(oids)}
    old = _reusable(path, meta) if reuse else {}
    fresh = [o for o in oids if o not in old]
    kept = [old[o] for o in oids if o in old]
    chunks = itertools.chain([kept], _embed_all(repo, fresh, backend, caps, workers))
    truncated = write(path, chunks, meta)
    return {"path": path.as_posix(), "runs": len(oids), "embedded": len(fresh),
            "reused": len(oids) - len(fresh), "truncated": truncated}  # fmt: skip


def write(path: Path, chunks: Any, meta: dict[str, str]) -> int:
    """Stage rows (``embed_rows`` tuples, in chunks) and *meta*, move into place; truncated."""
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(f"{path.name}.{os.getpid()}.staged")
    staged.unlink(missing_ok=True)
    with closing(sqlite3.connect(staged)) as db:
        db.executescript("PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;" + _SCHEMA)
        insert = "INSERT INTO transcripts VALUES (?, ?, ?, ?, ?, ?, ?)"
        for rows in chunks:
            db.executemany(insert, rows)
        truncated = db.execute("SELECT COUNT(*) FROM transcripts WHERE truncated").fetchone()[0]
        db.executemany("INSERT INTO meta VALUES (?, ?)", sorted(meta.items()))
        db.commit()
    os.replace(staged, path)
    return int(truncated)


def read_meta(path: Path) -> dict[str, str]:
    with closing(_ro(path)) as db:
        return dict(db.execute("SELECT key, value FROM meta"))


def staleness(repo: Any, backend: Any = None, caps: Caps = Caps()) -> dict[str, Any]:
    """``{"exists", "stale", "reasons"}`` against what a build now would record."""
    path = index_path(Path(repo.path))
    if not path.is_file():
        return {"exists": False, "stale": True, "reasons": ["the index has not been built"]}
    meta = read_meta(path)
    now = config(backend or te.HashBackend(), caps)
    reasons = [why for key, why in (
        ("format", "the index was written in another format"),
        ("backend_digest", "the embedding backend differs (backend digest)"),
        ("caps", "the size caps differ"), ("ann", "the search parameters differ"))
        if meta.get(key) != now[key]]  # fmt: skip
    oids = run_oids(repo)
    if meta.get("runs") != runs_digest(oids):
        reasons.append("runs were added or removed since the build")
    elif indexed_runs(path) != oids:
        reasons.append("the indexed runs differ from the repository's runs")
    return {"exists": True, "stale": bool(reasons), "reasons": reasons}


def _ro(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True)


def indexed_runs(path: Path) -> list[str]:
    with closing(_ro(path)) as db:
        return [r for (r,) in db.execute("SELECT run FROM transcripts ORDER BY run")]


def valid(vector: tuple[float, ...], dim: int) -> bool:
    """A unit vector of *dim* finite numbers (half-float rounding allowed)."""
    if len(vector) != dim or not all(math.isfinite(v) for v in vector):
        return False
    return abs(math.fsum(v * v for v in vector) - 1.0) <= 0.01


def load(path: Path, runs: Any = None, dim: int | None = None) -> tuple[ann.Index, dict, int]:
    """The search index, ``{run: {"steps", "bytes", "truncated", "text_sha256"}}`` and how
    many rows were left out: rows for runs not in *runs*, and vectors that are not unit
    vectors of *dim* finite numbers (the file is writable, so its rows are checked).
    """
    rows, info, rejected = [], {}, 0
    allowed = set(runs) if runs is not None else None
    with closing(_ro(path)) as db:
        for run, steps, size, cut, sha, vector, _keys in db.execute(
            "SELECT * FROM transcripts ORDER BY run"
        ):
            values = ann.unpack(vector) if isinstance(vector, bytes) else ()
            if (allowed is not None and run not in allowed) or not valid(
                values, dim or len(values)
            ):
                rejected += 1
                continue
            rows.append((run, values, None))
            info[run] = {"steps": steps, "bytes": size, "truncated": bool(cut),
                         "text_sha256": sha}  # fmt: skip
    return ann.Index(rows), info, rejected


def verify_rows(repo: Any, path: Path, backend: Any = None, caps: Caps = Caps()) -> list[str]:
    """Runs whose row disagrees with the objects: another transcript sha256, or a vector
    more than rounding away from embedding the transcript again."""
    backend = backend or te.HashBackend()
    read, bad, runs = reader(repo), [], set(run_oids(repo))
    with closing(_ro(path)) as db:
        rows = list(db.execute("SELECT run, text_sha256, vector FROM transcripts ORDER BY run"))
    for run, sha, vector in rows:
        doc = transcript(repo, run, caps, read) if run in runs else None
        if doc is None or hashlib.sha256(doc.text.encode("utf-8")).hexdigest() != sha:
            bad.append(run)
            continue
        again = backend.embed([doc.text])[0]
        stored = ann.unpack(vector) if isinstance(vector, bytes) else ()
        if len(stored) != len(again) or not ann.dot(again, stored) >= 0.999:
            bad.append(run)
    return bad


__all__ = ["AUTHORITY", "FORMAT", "build", "config", "embed_rows", "index_path", "load",
           "indexed_runs", "read_meta", "run_oids", "runs_digest", "staleness", "text_rows",
           "valid", "verify_rows", "write"]  # fmt: skip
