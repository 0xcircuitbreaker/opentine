"""Taint follows content in ``tine dataset curate`` (0.75 review).

A loop can copy a tainted trajectory into a new run (a new id, the same or
nearly the same text) so that no taint record names the copy. The filter
therefore also leaves out every candidate whose content-defined chunks overlap
a tainted run's chunks by at least :data:`NEAR` of the candidate's chunks,
or that contain at least :data:`NEAR` of one tainted run's distinct chunks,
so padding a copy with new text does not dilute it below the threshold (the
same FastCDC parameters as dedup, so a renamed copy overlaps fully and an
edit only changes the chunks around it). Such runs are listed in
``taint_filter.excluded`` like any tainted run; a justification that names
the copy lets it in, as for a run a record names.
"""

from __future__ import annotations

import hashlib
from typing import Any

from opentine._dataset_claims import CHUNKING

NEAR = 0.5


def _chunks(repo: Any, run: str, classifier: Any) -> list[bytes]:
    from opentine.remote._fastcdc import ChunkParams, chunks
    from opentine.repository._embed_index import redacted_text

    text = (redacted_text(repo, run, classifier) or "").replace(run, "")
    params = ChunkParams(CHUNKING["min"], CHUNKING["avg"], CHUNKING["max"])
    return [hashlib.sha256(c).digest() for c in chunks(text.encode("utf-8"), params)]


def copies(repo: Any, tainted: set[str], candidates: list[str]) -> set[str]:
    """The *candidates* outside *tainted* whose content is a (near) copy of a tainted run."""
    from opentine._pii_classify import load as load_classifier

    rest = [r for r in candidates if r not in tainted]
    if not tainted or not rest:
        return set()
    classifier = load_classifier()
    each: list[set[bytes]] = []
    for run in sorted(tainted):
        if repo.has(run):
            found = set(_chunks(repo, run, classifier))
            if found:
                each.append(found)
    bad = set().union(*each)
    out = set()
    for run in rest:
        mine = _chunks(repo, run, classifier)
        if not mine:
            continue
        have = set(mine)
        if sum(c in bad for c in mine) >= NEAR * len(mine) or any(
            len(found & have) >= NEAR * len(found) for found in each
        ):
            out.add(run)
    return out


__all__ = ["NEAR", "copies"]
