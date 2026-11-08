"""The derived embedding index at ``.tine/index/embed.sqlite`` (0.46).

Like the FTS5 index it is never authoritative: delete it and the next hybrid
search writes it again. Every vector is computed over **redacted** text only:
the run's indexed text (:func:`opentine.repository._search_index.extract`)
goes through the credential redactor (``opentine-redaction/2``) and then the
PII detectors and classifier (``opentine-redaction/3``) before an embedder sees
it, so neither a secret nor a person's details can be recovered from, or
matched through, a vector.

Vectors are keyed by run and embedder name: switching embedders re-embeds,
and :func:`refresh` embeds only runs it has not seen, so the index catches up
at query time instead of on every write.
"""

from __future__ import annotations

import sqlite3
import sys
from array import array
from contextlib import closing
from pathlib import Path
from typing import TYPE_CHECKING, Any

from opentine.repository._embed import normalise

if TYPE_CHECKING:
    from opentine.repository.store import Repo

INDEX_FORMAT = "opentine-embed/1"
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS vectors(run_id TEXT NOT NULL, embedder TEXT NOT NULL,"
    " dim INTEGER NOT NULL, vec BLOB NOT NULL, PRIMARY KEY(run_id, embedder))",
)
BATCH = 64


def index_path(repo: Repo) -> Path:
    return Path(repo.path) / "index" / "embed.sqlite"


def redacted_text(repo: Repo, run_id: str, classifier: Any) -> str | None:
    """The run's indexed text with credentials and PII removed, or None for a non-run."""
    from opentine._pii import redact_text
    from opentine.redaction import redact_blob
    from opentine.repository._search_index import extract

    extracted = extract(repo, run_id)
    if extracted is None:
        return None
    _, docs = extracted
    raw = "\n".join(docs).encode("utf-8", "replace")
    text = redact_blob(raw).decode("utf-8", "replace")
    return redact_text(text, classifier)[0]


def _pack(vector: list[float]) -> bytes:
    packed = array("f", vector)
    if sys.byteorder == "big":
        packed.byteswap()
    return packed.tobytes()


def _unpack(blob: bytes) -> list[float]:
    packed = array("f")
    packed.frombytes(blob)
    if sys.byteorder == "big":
        packed.byteswap()
    return list(packed)


def _open(repo: Repo) -> sqlite3.Connection:
    path = index_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    for statement in _SCHEMA:
        connection.execute(statement)
    row = connection.execute("SELECT value FROM meta WHERE key = 'format'").fetchone()
    if row is None:
        connection.execute("INSERT INTO meta VALUES ('format', ?)", (INDEX_FORMAT,))
    elif row != (INDEX_FORMAT,):
        connection.close()
        path.unlink()
        return _open(repo)
    return connection


def refresh(repo: Repo, run_ids: list[str], embedder: Any, classifier: Any) -> int:
    """Embed the runs among *run_ids* the index does not hold for *embedder*."""
    with closing(_open(repo)) as connection, connection:
        have = {
            row[0]
            for row in connection.execute(
                "SELECT run_id FROM vectors WHERE embedder = ?", (embedder.name,)
            )
        }
        todo = [run_id for run_id in run_ids if run_id not in have]
        added = 0
        for start in range(0, len(todo), BATCH):
            texts = {
                run_id: redacted_text(repo, run_id, classifier) for run_id in todo[start:][:BATCH]
            }
            pairs = [(run_id, text) for run_id, text in texts.items() if text is not None]
            vectors = embedder.embed([text for _, text in pairs]) if pairs else []
            if len(vectors) != len(pairs):
                raise ValueError(f"embedder {embedder.name} returned the wrong number of vectors")
            for (run_id, _), vector in zip(pairs, vectors, strict=True):
                if len(vector) != embedder.dim:
                    raise ValueError(f"embedder {embedder.name} returned a vector of wrong size")
                connection.execute(
                    "INSERT OR REPLACE INTO vectors VALUES (?, ?, ?, ?)",
                    (run_id, embedder.name, embedder.dim, _pack(normalise(list(vector)))),
                )
                added += 1
        return added


def _scores(query: list[float], rows: list[tuple[str, bytes]]) -> list[tuple[float, str]]:
    try:
        import numpy as np
    except ImportError:  # the ``embed`` extra is optional: same answer, pure Python
        return [(sum(a * b for a, b in zip(query, _unpack(blob), strict=False)), run_id)
                for run_id, blob in rows]  # fmt: skip
    if not rows:
        return []
    matrix = np.frombuffer(b"".join(blob for _, blob in rows), dtype="<f4").reshape(len(rows), -1)
    found = matrix @ np.asarray(query, dtype="<f4")
    return [(float(score), run_id) for score, (run_id, _) in zip(found, rows, strict=True)]


def nearest(repo: Repo, query: str, embedder: Any, run_ids: set[str], k: int) -> list[str]:
    """Up to *k* of *run_ids*, most similar to *query* first (ties by run id)."""
    vector = normalise(list(embedder.embed([query])[0]))
    with closing(_open(repo)) as connection:
        rows = [
            (run_id, blob)
            for run_id, blob in connection.execute(
                "SELECT run_id, vec FROM vectors WHERE embedder = ? AND dim = ?",
                (embedder.name, embedder.dim),
            )
            if run_id in run_ids
        ]
    ranked = sorted(_scores(vector, rows), key=lambda item: (-round(item[0], 6), item[1]))
    return [run_id for score, run_id in ranked[:k] if score > 0]


__all__ = ["INDEX_FORMAT", "index_path", "nearest", "redacted_text", "refresh"]
