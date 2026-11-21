"""Behaviour flags and runs like them in the oversight queue (0.74).

:func:`items` feeds the ``transcript`` source of the 0.63 oversight queue
(:mod:`opentine._oversight_queue`):

* ``transcript:<attestation>`` -- every **verified** behaviour flag
  (:mod:`opentine._transcript_flags`), with the flag's label;
* ``transcript:<label>:<run>`` -- every run whose transcript is like one of a
  verified flag's evidence runs (centred cosine at or above
  :data:`SIMILAR_THRESHOLD` in the ``opentine.tfidf-hash/1`` space fitted on
  the repository's redacted runs; 0.76: the best of the whole run and its
  word windows, :mod:`opentine._transcript_windows`, so padding cannot dilute
  it), a "similar to known bad" hit, labelled like the flag. 0.76: every run
  at or above the threshold is a hit, not only the nearest 50, so decoys that
  copy the evidence cannot push a real hit out; past :data:`MAX_SIMILAR_HITS`
  the best are kept and the truncation is reported.

An item reaches a tier only through a ``[[route]] source = "transcript"`` row
of the pinned policy (``label`` is a glob over the flag label), so nothing
blocks by default. The similarity is recomputed from the objects every time
the queue is built; there is no stored index to plant rows in. An unverified
flag (forged, unpinned or optimizer signer) opens nothing and seeds nothing.
"""

from __future__ import annotations

import warnings
from typing import Any

SOURCE = "transcript"
SIMILAR_THRESHOLD = 0.6
MAX_SIMILAR_HITS = 10_000  # a work bound, never a ranking cut (truncation is reported)


def verified_flags(repo: Any) -> list[dict[str, Any]]:
    from opentine._transcript_flags import flags

    return [f for f in flags(repo) if f["verification"] == "verified"]


def similar_report(repo: Any, verified: list[dict[str, Any]], *,
                   threshold: float = SIMILAR_THRESHOLD) -> dict[str, Any]:  # fmt: skip
    """``{"hits": {(label, run): {"score", "like"}}, "truncated": bool}``.

    Every run at or above *threshold* against any evidence run is a hit (no
    top-k, so copies of the evidence cannot push a real hit out). Past
    :data:`MAX_SIMILAR_HITS` the best-scoring hits are kept, ``truncated`` is
    true and a :class:`RuntimeWarning` says so.
    """
    flagged = {(f["label"], run) for f in verified for run in f["evidence"] or []}
    if not flagged:
        return {"hits": {}, "truncated": False}
    from opentine._transcript_corpus import from_repo
    from opentine._transcript_windows import scorer

    score = scorer(from_repo(repo), sorted({like for _, like in flagged}))
    space = score.space
    hits: dict[tuple[str, str], dict[str, Any]] = {}
    for label, like in sorted(flagged):
        if like not in space.vectors:
            continue
        query = space.query([space.vectors[like]])
        width = score.width(like)
        for run in space.ids:
            key = (label, run)
            if run == like or key in flagged:
                continue
            value = round(score.best(query, run, width), 6)
            if value >= threshold and (key not in hits or hits[key]["score"] < value):
                hits[key] = {"score": value, "like": like}
    truncated = len(hits) > MAX_SIMILAR_HITS
    if truncated:
        best = sorted(hits, key=lambda k: (-hits[k]["score"], k))[:MAX_SIMILAR_HITS]
        hits = {k: hits[k] for k in best}
        warnings.warn(f"similar-to-known-bad hits truncated to the {MAX_SIMILAR_HITS} "
                      "best-scoring runs", RuntimeWarning, stacklevel=2)  # fmt: skip
    return {"hits": hits, "truncated": truncated}


def similar_hits(
    repo: Any, verified: list[dict[str, Any]], *, threshold: float = SIMILAR_THRESHOLD
) -> dict[tuple[str, str], dict[str, Any]]:
    """``{(label, run): {"score", "like"}}`` for runs like a verified flag's evidence."""
    return similar_report(repo, verified, threshold=threshold)["hits"]


def items(repo: Any) -> list[dict[str, Any]]:
    """Oversight-queue source rows for flags and similar-to-known-bad runs."""
    verified = verified_flags(repo)
    out = [{"item": f"{SOURCE}:{f['record']}", "source": SOURCE, "label": f["label"]}
           for f in verified]  # fmt: skip
    for (label, run), _ in sorted(similar_hits(repo, verified).items()):
        out.append({"item": f"{SOURCE}:{label}:{run}", "source": SOURCE, "label": label})
    return out


__all__ = ["MAX_SIMILAR_HITS", "SIMILAR_THRESHOLD", "SOURCE", "items", "similar_hits",
           "similar_report", "verified_flags"]  # fmt: skip
