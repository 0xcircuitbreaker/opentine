"""Embedding near-duplicates for ``tine dataset contamination`` (0.74).

``--embedding-threshold T`` adds a third check to the 0.60 exact and MinHash
checks: every holdout item and corpus item (same text as
:func:`opentine._contamination.item_text`) is embedded in one
:class:`~opentine._transcript_embed.Space` fitted over both, and a pair whose
cosine similarity is at or above ``T`` is reported with its score. The
result records the backend (name, parameter digest, weights digest for a
pinned model), the threshold and how many pairs were compared, so a reader can
redo it. It catches paraphrases that keep the vocabulary but break the word
5-gram shingles (reordered clauses, swapped connectives). Cost is one sparse
dot product per holdout x corpus pair.
"""

from __future__ import annotations

from typing import Any

THRESHOLD = 0.9


def check(holdout: list[dict[str, Any]], corpus: list[tuple[str, dict[str, Any]]], *,
          threshold: float = THRESHOLD, model: Any = None) -> dict[str, Any]:  # fmt: skip
    """``{"backend", "threshold", "compared", "near": [{"id", "found_in", "cosine"}]}``."""
    from opentine._contamination import item_text
    from opentine._transcript_embed import Space, dot

    if not 0.0 < threshold <= 1.0:
        raise ValueError("the embedding threshold is in (0, 1]")
    texts = {f"h\x00{i}": item_text(item) for i, item in enumerate(holdout)}
    texts.update({f"c\x00{i}": item_text(item) for i, (_, item) in enumerate(corpus)})
    space = Space(texts, model=model)
    near, compared = [], 0
    for i, item in enumerate(holdout):
        mine = space.vectors[f"h\x00{i}"]
        for j, (where, _) in enumerate(corpus):
            compared += 1
            score = dot(mine, space.vectors[f"c\x00{j}"])
            if score >= threshold:
                near.append({"id": str(item.get("id")), "found_in": where,
                             "cosine": round(score, 6)})  # fmt: skip
    return {"backend": space.backend(), "threshold": threshold, "compared": compared,
            "near": near}  # fmt: skip


__all__ = ["THRESHOLD", "check"]
