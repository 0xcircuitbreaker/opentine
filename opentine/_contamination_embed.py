"""Embedding near-duplicates for ``tine dataset contamination`` (0.74, release 0.73.0).

Opt-in with ``--embedding-threshold T``: each holdout item's text
(:func:`opentine._contamination.item_text`) and each corpus item's text are
embedded with the transcript backend (:mod:`opentine._transcript_embed`,
``transcript-hash/1`` unless ``--embedding-backend`` names a local model), and
a holdout item whose nearest corpus items have cosine similarity at or above
``T`` is reported under ``embedding.near``. The backend digest and the
threshold are recorded in the result so a reader can redo the check.

This catches rewordings that keep the vocabulary but break word 5-gram
overlap (reordered clauses, changed function words), which the MinHash check
misses by design. An exact or MinHash hit is not repeated here.
"""

from __future__ import annotations

from typing import Any

from opentine import _transcript_ann as ann
from opentine import _transcript_embed as te
from opentine._contamination import item_text

NEIGHBOURS = 5


def check(holdout: list[dict[str, Any]], corpus: list[tuple[str, dict[str, Any]]], *,
          threshold: float, backend: Any = None,
          skip: frozenset[str] = frozenset()) -> dict[str, Any]:  # fmt: skip
    """``{"backend", "backend_digest", "threshold", "near": [{"id", "found_in", "cosine"}]}``."""
    if not 0.0 < threshold <= 1.0:
        raise ValueError("the embedding threshold is in (0, 1]")
    backend = backend or te.HashBackend()
    vectors = backend.embed([item_text(item) for _, item in corpus])
    index = ann.Index((str(i), v, None) for i, v in enumerate(vectors))
    near = []
    for item in holdout:
        ident = str(item.get("id"))
        if ident in skip or not len(index):
            continue
        query = backend.embed([item_text(item)])[0]
        found = index.search(query, min(NEIGHBOURS, len(index)))
        for hit in found["hits"]:
            if hit["score"] >= threshold:
                near.append({"id": ident, "found_in": corpus[int(hit["run"])][0],
                             "cosine": hit["score"]})  # fmt: skip
    return {"backend": backend.description()["name"], "backend_digest": te.backend_digest(backend),
            "threshold": threshold, "near": near}  # fmt: skip


__all__ = ["NEIGHBOURS", "check"]
