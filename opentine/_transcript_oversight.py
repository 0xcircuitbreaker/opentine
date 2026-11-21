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
  it), a "similar to known bad" hit, labelled like the flag.

An item reaches a tier only through a ``[[route]] source = "transcript"`` row
of the pinned policy (``label`` is a glob over the flag label), so nothing
blocks by default. The similarity is recomputed from the objects every time
the queue is built; there is no stored index to plant rows in. An unverified
flag (forged, unpinned or optimizer signer) opens nothing and seeds nothing.
"""

from __future__ import annotations

from typing import Any

SOURCE = "transcript"
SIMILAR_THRESHOLD = 0.6
SIMILAR_TOP = 50


def verified_flags(repo: Any) -> list[dict[str, Any]]:
    from opentine._transcript_flags import flags

    return [f for f in flags(repo) if f["verification"] == "verified"]


def similar_hits(repo: Any, verified: list[dict[str, Any]], *,
                 threshold: float = SIMILAR_THRESHOLD,
                 top: int = SIMILAR_TOP) -> dict[tuple[str, str], dict[str, Any]]:  # fmt: skip
    """``{(label, run): {"score", "like"}}`` for runs like a verified flag's evidence."""
    flagged = {(f["label"], run) for f in verified for run in f["evidence"] or []}
    if not flagged:
        return {}
    from opentine._transcript_corpus import from_repo
    from opentine._transcript_windows import scorer

    score = scorer(from_repo(repo))
    space = score.space
    hits: dict[tuple[str, str], dict[str, Any]] = {}
    for label, like in sorted(flagged):
        if like not in space.vectors:
            continue
        query = space.query([space.vectors[like]])
        width = score.width(like)
        rows = [(round(score.best(query, i, width), 6), i) for i in space.ids if i != like]
        for value, run in sorted(rows, key=lambda r: (-r[0], r[1]))[:top]:
            if value < threshold:
                break
            row = {"run": run, "score": value}
            key = (label, row["run"])
            if key in flagged or (key in hits and hits[key]["score"] >= row["score"]):
                continue
            hits[key] = {"score": row["score"], "like": like}
    return hits


def items(repo: Any) -> list[dict[str, Any]]:
    """Oversight-queue source rows for flags and similar-to-known-bad runs."""
    verified = verified_flags(repo)
    out = [{"item": f"{SOURCE}:{f['record']}", "source": SOURCE, "label": f["label"]}
           for f in verified]  # fmt: skip
    for (label, run), _ in sorted(similar_hits(repo, verified).items()):
        out.append({"item": f"{SOURCE}:{label}:{run}", "source": SOURCE, "label": label})
    return out


__all__ = ["SIMILAR_THRESHOLD", "SIMILAR_TOP", "SOURCE", "items", "similar_hits",
           "verified_flags"]  # fmt: skip
