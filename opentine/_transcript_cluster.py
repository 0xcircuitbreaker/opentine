"""Seeded clustering, similarity search and the recall@k evaluation (0.74).

Clustering is spherical k-means over a :class:`~opentine._transcript_embed.Space`:
runs are taken in sorted id order, initial centres by k-means++ from
``random.Random(seed)``, then at most ``ITERATIONS`` rounds of assign (highest
dot product, ties to the lower centre index) and re-centre, stopping early
when no assignment changes. Same corpus, backend, ``k`` and seed: same
clusters. A cluster's id is ``tc-`` and the first 16 hex digits of the
SHA-256 of its sorted member ids, so it names its members, not its position.

:func:`similar` ranks runs by centred similarity to the centroid of one or
more exemplar runs ("find trajectories like these"). :func:`recall_at` is the
seeded-behaviour evaluation: for each behaviour, the first ``exemplars``
seeded transcripts (by id) are the labelled evidence, every other transcript
is ranked, and recall is the share of the remaining seeded transcripts of
that behaviour in the top ``k``. It is count based and deterministic.
"""

from __future__ import annotations

import hashlib
import math
import random
from typing import Any

from opentine._transcript_embed import Space, Sparse, dot

ITERATIONS = 25
MAX_K = 1000


def default_k(n: int) -> int:
    return max(1, min(MAX_K, round(math.sqrt(n / 2)))) if n else 0


def cluster_id(members: list[str]) -> str:
    return "tc-" + hashlib.sha256("\n".join(sorted(members)).encode("utf-8")).hexdigest()[:16]


def _centre(vectors: list[Sparse], dim: int) -> list[float]:
    out = [0.0] * dim
    for vector in vectors:
        for k, v in vector.items():
            out[k] += v
    norm = math.sqrt(sum(v * v for v in out))
    return [v / norm for v in out] if norm else out


def _seeds(space: Space, k: int, rng: random.Random) -> list[list[float]]:
    ids = space.ids
    first = space.vectors[ids[rng.randrange(len(ids))]]
    centres = [_centre([first], space.dim)]
    best = {i: dot(space.vectors[i], centres[0]) for i in ids}
    while len(centres) < k:
        weights = [max(0.0, 1.0 - best[i]) ** 2 for i in ids]
        total = sum(weights)
        if total <= 0:
            break
        pick, acc = rng.random() * total, 0.0
        chosen = ids[-1]
        for i, w in zip(ids, weights, strict=True):
            acc += w
            if acc >= pick:
                chosen = i
                break
        centres.append(_centre([space.vectors[chosen]], space.dim))
        for i in ids:
            best[i] = max(best[i], dot(space.vectors[i], centres[-1]))
    return centres


def kmeans(space: Space, k: int | None = None, seed: int = 0) -> dict[str, Any]:
    """``{"k", "seed", "iterations", "clusters": [{"id", "size", "members", "exemplar"}]}``."""
    ids = space.ids
    k = min(len(ids), default_k(len(ids)) if k is None else k)
    if k < 0 or k > MAX_K:
        raise ValueError(f"k is in 1..{MAX_K}")
    if not ids or k == 0:
        return {"k": 0, "seed": seed, "iterations": 0, "clusters": []}
    centres = _seeds(space, k, random.Random(seed))
    assign: dict[str, int] = {}
    rounds = 0
    for rounds in range(1, ITERATIONS + 1):  # noqa: B007 - the count is reported
        fresh = {}
        for i in ids:
            scores = [dot(space.vectors[i], c) for c in centres]
            fresh[i] = max(range(len(centres)), key=lambda j: (scores[j], -j))
        if fresh == assign:
            break
        assign = fresh
        groups = [[space.vectors[i] for i in ids if assign[i] == j] for j in range(len(centres))]
        centres = [_centre(g, space.dim) if g else c for g, c in zip(groups, centres, strict=True)]
    clusters = []
    for j, centre in enumerate(centres):
        members = [i for i in ids if assign[i] == j]
        if members:
            exemplar = max(members, key=lambda i: (dot(space.vectors[i], centre), i))
            clusters.append({"id": cluster_id(members), "size": len(members),
                             "members": members, "exemplar": exemplar})  # fmt: skip
    clusters.sort(key=lambda c: (-c["size"], c["id"]))
    return {"k": len(clusters), "seed": seed, "iterations": rounds, "clusters": clusters}


def similar(space: Space, exemplars: list[str], top: int) -> list[dict[str, Any]]:
    """Up to *top* runs most like the *exemplars* (exemplars excluded), best first."""
    missing = [e for e in exemplars if e not in space.vectors]
    if missing:
        raise KeyError(f"not in the analysed corpus: {missing[0]}")
    query = space.query([space.vectors[e] for e in exemplars])
    rows = [(round(space.score(query, i), 6), i) for i in space.ids if i not in set(exemplars)]
    rows.sort(key=lambda r: (-r[0], r[1]))
    return [{"run": i, "score": s} for s, i in rows[:top]]


def recall_at(space: Space, behaviours: dict[str, str], *, k: int = 50,
              exemplars: int = 5) -> dict[str, Any]:  # fmt: skip
    """Per-behaviour recall@k of seeded transcripts (``behaviours``: id -> behaviour)."""
    out: dict[str, Any] = {}
    for name in sorted({b for b in behaviours.values() if b != "none"}):
        seeded = sorted(i for i, b in behaviours.items() if b == name)
        evidence, rest = seeded[:exemplars], set(seeded[exemplars:])
        found = {r["run"] for r in similar(space, evidence, k)} & rest
        recall = len(found) / len(rest) if rest else 1.0
        out[name] = {"seeded": len(seeded), "exemplars": len(evidence), "relevant": len(rest),
                     "found": len(found), "recall": recall}  # fmt: skip
    return {"k": k, "exemplars": exemplars, "behaviours": out,
            "min_recall": min((v["recall"] for v in out.values()), default=1.0)}  # fmt: skip


__all__ = ["ITERATIONS", "MAX_K", "cluster_id", "default_k", "kmeans", "recall_at", "similar"]
