"""Judge ensembles (0.89): independent members, one vote per independent group.

An ensemble is a list of members, each a judge provenance document
(:mod:`opentine._judge_provenance`) plus, when known, its prompt text and a
declared ``lineage`` (the name of the lineage or family it was derived in).
Two members are *dependent* when any of these holds:

* the same ``model``;
* the same ``prompt_digest``;
* the same declared ``lineage``;
* prompt texts whose similarity (:func:`similarity`) reaches the threshold
  (default 0.8): a fork of one prompt with a small edit is still one judge.

Dependence is transitive (union-find), so the members fall into *groups*, and
copies of one judge count once: each group casts one vote, the majority of
its members' labels (a tie inside a group is an abstain of that group).
:func:`independence` reports the groups; fewer independent groups than
``min_independent`` is ``fail:judge.ensemble-not-independent`` (a command-level
code, not a ``tine verify`` code).

Aggregation over the group votes (abstains and errors never count as votes):

``majority``  the most frequent label; a tie, or no votes, is an abstain;
``mean``      (two labels) the mean of each group's score for the ``positive`` label
              (``p`` when it voted for it, ``1 - p`` otherwise, ``p`` defaulting
              to 1); the label is ``positive`` when the mean is at least 0.5;
``min``       the same with the minimum: the most sceptical group decides.

When more than ``max_abstain`` of the groups abstain or err the ensemble
abstains: an ensemble that mostly declined has not decided.
"""

from __future__ import annotations

import re
from collections import Counter
from fractions import Fraction
from typing import Any

AGGREGATES = ("majority", "mean", "min")
THRESHOLD = Fraction(4, 5)
_SPACE = re.compile(r"\s+")
MAX_TEXT = 1 << 16


def _shingles(text: str, size: int = 4) -> set[str]:
    norm = _SPACE.sub(" ", text[:MAX_TEXT].casefold()).strip()
    if len(norm) < size:
        return {norm}
    return {norm[i : i + size] for i in range(len(norm) - size + 1)}


def similarity(left: str, right: str) -> Fraction:
    """Jaccard similarity of character 4-gram sets (case and spacing folded)."""
    a, b = _shingles(left), _shingles(right)
    return Fraction(len(a & b), len(a | b)) if a | b else Fraction(1)


def _reasons(a: dict[str, Any], b: dict[str, Any], threshold: Fraction) -> list[str]:
    why = []
    if a["provenance"]["model"] == b["provenance"]["model"]:
        why.append("model")
    if a["provenance"]["prompt_digest"] == b["provenance"]["prompt_digest"]:
        why.append("prompt_digest")
    if a.get("lineage") and a.get("lineage") == b.get("lineage"):
        why.append("lineage")
    if a.get("prompt") and b.get("prompt") and "prompt_digest" not in why:
        if similarity(a["prompt"], b["prompt"]) >= threshold:
            why.append("prompt_similar")
    return why


def independence(members: list[dict[str, Any]], *, min_independent: int = 2,
                 threshold: Fraction = THRESHOLD) -> dict[str, Any]:  # fmt: skip
    """``{"groups", "independent", "links", "findings"}`` for an ensemble's members."""
    parent = list(range(len(members)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    links = []
    for i in range(len(members)):
        for j in range(i + 1, len(members)):
            why = _reasons(members[i], members[j], threshold)
            if why:
                links.append({"members": [i, j], "because": why})
                parent[root(j)] = root(i)
    groups: dict[int, list[int]] = {}
    for i in range(len(members)):
        groups.setdefault(root(i), []).append(i)
    rows = sorted(groups.values())
    findings = []
    if len(rows) < min_independent:
        detail = (f"{len(rows)} independent judge group(s) among {len(members)} member(s); "
                  f"{min_independent} needed")  # fmt: skip
        findings.append({"code": "fail:judge.ensemble-not-independent", "detail": detail})
    return {"groups": rows, "independent": len(rows), "links": links, "findings": findings}


def _group_vote(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    labelled = [o for o in outcomes if o.get("status") == "label"]
    if not labelled:
        return {"status": "abstain", "label": None, "probability": None}
    counts = Counter(o["label"] for o in labelled).most_common()
    if len(counts) > 1 and counts[0][1] == counts[1][1]:
        return {"status": "abstain", "label": None, "probability": None}
    best = [o for o in labelled if o["label"] == counts[0][0]]
    probs = [Fraction(o["probability"]) for o in best if o.get("probability") is not None]
    prob = sum(probs, Fraction(0)) / len(probs) if probs else None
    return {"status": "label", "label": counts[0][0], "probability": prob}


def _text(value: Fraction) -> str:
    return format(float(value), ".6f")


def aggregate(outcomes: list[dict[str, Any]], groups: list[list[int]], *, method: str = "majority",
              positive: str | None = None, labels: list[str] | None = None,
              max_abstain: Fraction = Fraction(1, 2)) -> dict[str, Any]:  # fmt: skip
    """The ensemble's outcome for one item; *outcomes* are per member, in member order."""
    if method not in AGGREGATES:
        raise ValueError(f"aggregate is one of {', '.join(AGGREGATES)}")
    if method != "majority" and (not labels or len(labels) != 2 or positive not in labels):
        raise ValueError(f"the {method} aggregate needs two labels and a positive one")
    votes = [_group_vote([outcomes[i] for i in group]) for group in groups]
    cast = [v for v in votes if v["status"] == "label"]
    base = {"votes": len(cast), "groups": len(groups)}
    if not cast or Fraction(len(groups) - len(cast), len(groups)) > max_abstain:
        return {"status": "abstain", "label": None, "probability": None, **base}
    if method == "majority":
        counts = Counter(v["label"] for v in cast).most_common()
        if len(counts) > 1 and counts[0][1] == counts[1][1]:
            return {"status": "abstain", "label": None, "probability": None, **base}
        share = Fraction(counts[0][1], len(cast))
        return {"status": "label", "label": counts[0][0], "probability": _text(share), **base}
    scores = []
    for v in cast:
        p = v["probability"] if v["probability"] is not None else Fraction(1)
        scores.append(p if v["label"] == positive else 1 - p)
    value = sum(scores, Fraction(0)) / len(scores) if method == "mean" else min(scores)
    negative = next(x for x in labels or () if x != positive)
    label = positive if value >= Fraction(1, 2) else negative
    return {"status": "label", "label": label, "probability": _text(value), **base}


__all__ = ["AGGREGATES", "THRESHOLD", "aggregate", "independence", "similarity"]
