"""Code search over a tenant's mirror (0.55): the ``repo-search --hybrid`` ranking, per tenant.

The cache is ``<mirror>/search.sqlite3``, inside the tenant's mirror
directory, so one tenant's index can never answer another's query and
unlinking deletes it with the mirror. It holds the text files of the default
branch head (at most :data:`MAX_FILES`, each at most :data:`MAX_FILE_BYTES`):
an FTS5 table ranked by BM25 (when SQLite has FTS5) and ``hash-ngram/1``
vectors (:class:`opentine.repository._embed.HashEmbedder`, deterministic and
local), fused by reciprocal rank fusion exactly as ``repo-search --hybrid``
fuses runs (:func:`opentine.repository._hybrid.fuse`). The index is derived
and rebuilt on every successful sync; it is never authoritative.
"""

from __future__ import annotations

import math
import sqlite3
import struct
from contextlib import closing
from pathlib import Path
from typing import Any

from opentine import _mirror_git as gitio
from opentine.remote import _mirror_store as store
from opentine.repository._embed import HashEmbedder
from opentine.repository._hybrid import fuse
from opentine.repository._search_index import fts5_available
from opentine.repository._search_query import _WORD, fts_query

MAX_FILES = 5000
MAX_FILE_BYTES = 256 * 1024
MAX_HITS = 50
_EMBED_CHARS = 8192


def _path(root: Path, tenant: str) -> Path:
    return store.directory(root, tenant) / "search.sqlite3"


def _files(repo: Path, commit: str, prefix: str = "", out=None) -> list[tuple[str, str]]:
    out = [] if out is None else out
    for entry in gitio.tree(repo, commit, prefix):
        if len(out) >= MAX_FILES:
            break
        if entry["type"] == "tree":
            _files(repo, commit, entry["path"], out)
        elif entry["type"] == "blob" and (entry["size"] or 0) <= MAX_FILE_BYTES:
            _, data, _ = gitio.blob(repo, commit, entry["path"], MAX_FILE_BYTES)
            if data is not None and b"\0" not in data[:8000]:
                out.append((entry["path"], data.decode("utf-8", "replace")))
    return out


def rebuild(root: Path, tenant: str, branch: str) -> int:
    """Re-index the default branch head; the number of files indexed."""
    target = _path(root, tenant)
    target.unlink(missing_ok=True)
    try:
        commit = gitio.resolve(store.repo(root, tenant), branch)
    except gitio.Missing:
        return 0
    files = _files(store.repo(root, tenant), commit)
    vectors = HashEmbedder().embed([text[:_EMBED_CHARS] for _, text in files])
    with closing(sqlite3.connect(target)) as db, db:
        db.execute("CREATE TABLE files (path TEXT PRIMARY KEY, body TEXT, vec BLOB)")
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        db.execute("INSERT INTO meta VALUES ('commit', ?)", (commit,))
        db.executemany("INSERT INTO files VALUES (?, ?, ?)",
                       [(p, t, struct.pack(f"<{len(v)}f", *v)) for (p, t), v in
                        zip(files, vectors, strict=True)])  # fmt: skip
        if fts5_available():
            db.execute("CREATE VIRTUAL TABLE fts USING fts5(path, body)")
            db.execute("INSERT INTO fts SELECT path, body FROM files")
    return len(files)


def _line(text: str, words: list[str]) -> tuple[int, str]:
    folded = [w.casefold() for w in words]
    for number, line in enumerate(text.splitlines(), 1):
        if any(word in line.casefold() for word in folded):
            return number, line.strip()[:200]
    return 1, (text.splitlines() or [""])[0].strip()[:200]


def search(root: Path, tenant: str, query: str, limit: int = MAX_HITS) -> dict[str, Any]:
    """``{commit, hits: [{path, line, snippet}]}`` best first; no index is no hits."""
    words = _WORD.findall(query)
    path = _path(root, tenant)
    if not words or not path.is_file():
        return {"commit": None, "hits": []}
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
        commit = db.execute("SELECT value FROM meta WHERE key = 'commit'").fetchone()[0]
        rows = {p: (body, vec) for p, body, vec in db.execute("SELECT path, body, vec FROM files")}
        lexical: list[str] = []
        if (
            fts5_available()
            and db.execute("SELECT 1 FROM sqlite_master WHERE name='fts'").fetchone()
        ):
            lexical = [r[0] for r in db.execute(
                "SELECT path FROM fts WHERE fts MATCH ? ORDER BY bm25(fts) LIMIT 200",
                (fts_query(query),))]  # fmt: skip
        else:
            folded = [w.casefold() for w in words]
            lexical = sorted(
                name
                for name, (text, _) in rows.items()
                if all(w in text.casefold() or w in name.casefold() for w in folded)
            )
    probe = HashEmbedder().embed([query])[0]
    scored = []
    for name, (_, vec) in rows.items():
        values = struct.unpack(f"<{len(vec) // 4}f", vec)
        score = sum(a * b for a, b in zip(probe, values, strict=False))
        if score > 0 and not math.isnan(score):
            scored.append((-score, name))
    semantic = [name for _, name in sorted(scored)[:200]]
    lexical_set = set(lexical)
    ranked = [name for name in fuse(lexical, semantic) if name in lexical_set or not lexical]
    hits = []
    for name in ranked[: max(1, min(limit, MAX_HITS))]:
        number, snippet = _line(rows[name][0], words)
        hits.append({"path": name, "line": number, "snippet": snippet})
    return {"commit": commit, "hits": hits}


__all__ = ["MAX_FILES", "MAX_HITS", "rebuild", "search"]
