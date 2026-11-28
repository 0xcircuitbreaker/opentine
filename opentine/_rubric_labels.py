"""Human rubric labels and their queue (0.89): the ``opentine.rubric-label/1`` convention.

A human label is an **attestation** (the existing object kind) whose claim
binds the reviewer key, the rubric and the item::

    {"convention": "opentine.rubric-label/1", "rubric": "sha256:<rubric text>",
     "item": "ID", "item_digest": "sha256:<canonical item>", "label": "LABEL",
     "reviewer": "sha256:<fingerprint>", "at": "RFC 3339"}

It is held under ``rubric-label:<rubric digest>`` (``tine hold release``
refuses it), so a loop cannot delete a label it disagrees with.

A label counts only when all of these hold (:func:`labels`):

* its Ed25519 signature verifies and the payload ``signer`` is the key that
  signed (``used_key_fingerprint``), and ``reviewer`` is that same key;
* that key holds the ``reviewer`` role in the owner-pinned trust bundle
  (:mod:`opentine._key_roles_pin`) and is not an ``optimizer`` key;
* its rubric is the rubric asked about, and its ``item_digest`` is the digest of
  the item of that id in the dataset asked about (a label made for another
  version of the item does not carry over).

One reviewer with two different labels for one item is a conflict: neither
counts, and the conflict is reported. Recording refuses an unpinned or
optimizer reviewer up front (``judge.label-signer``).

The queue (:func:`queue`) assigns each item to ``per_item`` of the pinned
reviewers, chosen by ``sha256(item_digest || reviewer)`` order, so the
assignment is reproducible and no reviewer picks their own items; it lists each
reviewer's pending items and any labels made outside the assignment.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from opentine.repository._holds import RUBRIC_LABEL as HOLD

CONVENTION = "opentine.rubric-label/1"
ROLE = "reviewer"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
ITEM_RE = re.compile(r"[A-Za-z0-9_.:@/-]{1,256}")
FIELDS = ("convention", "rubric", "item", "item_digest", "label", "reviewer", "at")


class LabelError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def rubric_digest(text: bytes) -> str:
    return "sha256:" + hashlib.sha256(text).hexdigest()


def reviewers(repo: Any) -> tuple[set[str], str]:
    """Pinned ``reviewer`` keys that are not ``optimizer`` keys, and why another is not one."""
    from opentine._key_roles_pin import granting

    return granting(repo.path, ROLE)


def check_claim(claim: Any) -> list[str]:
    from opentine._judge_label import LABEL_RE

    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return ["not an opentine.rubric-label/1 claim"]
    if set(claim) != set(FIELDS):
        return ["fields are " + ", ".join(FIELDS)]
    problems = []
    for field in ("rubric", "item_digest", "reviewer"):
        if not isinstance(claim[field], str) or not DIGEST_RE.fullmatch(claim[field]):
            problems.append(f"{field} is sha256: + 64 hex")
    if not isinstance(claim["item"], str) or not ITEM_RE.fullmatch(claim["item"]):
        problems.append("item is a 1-256 character id")
    if not isinstance(claim["label"], str) or not LABEL_RE.fullmatch(claim["label"]):
        problems.append("label is 1-64 of A-Z a-z 0-9 _ . -")
    if not isinstance(claim["at"], str):
        problems.append("at is a time")
    return problems


def record(repo: Any, claim: dict[str, Any], key: Any) -> str:
    """Sign and hold one label; refuse a reviewer the trust bundle does not pin."""
    from opentine import _containment_records as records

    problems = check_claim(claim)
    if problems:
        raise LabelError("judge.label-invalid", problems[0])
    signer = records.fingerprint(key)
    allowed, why = reviewers(repo)
    if signer != claim["reviewer"] or signer not in allowed:
        raise LabelError("judge.label-signer", f"{signer}: {why}")
    anchor = records.anchor(repo, "rubric-label", f"{claim['rubric']} {claim['item']}")
    return records.record(repo, anchor, claim, key, HOLD + claim["rubric"])


def labels(repo: Any, rubric: str, items: dict[str, str]) -> dict[str, Any]:
    """``{"labels": {item: {reviewer: label}}, "ignored": [...], "conflicts": [...]}``.

    *items* maps item id to item digest; only labels bound to both count.
    """
    from opentine import _containment_records as records

    allowed, why = reviewers(repo)
    seen: dict[str, dict[str, set[str]]] = {}
    ignored = []
    for target, row in records.held(repo, HOLD + rubric):
        claim = row["claim"]
        reason = None
        if target != HOLD + rubric or check_claim(claim):
            reason = "not a rubric label for this rubric"
        elif not row["signed"] or claim["reviewer"] != row["signer"]:
            reason = "not signed by its reviewer key"
        elif row["signer"] not in allowed:
            reason = why
        elif claim["rubric"] != rubric:
            reason = "bound to another rubric"
        elif items.get(claim["item"]) != claim["item_digest"]:
            reason = "bound to another version of the item, or an unknown item"
        if reason:
            ignored.append({"oid": row["oid"], "reason": reason})
            continue
        seen.setdefault(claim["item"], {}).setdefault(claim["reviewer"], set()).add(claim["label"])
    out: dict[str, dict[str, str]] = {}
    conflicts = []
    for item, by in sorted(seen.items()):
        for reviewer, found in sorted(by.items()):
            if len(found) > 1:
                conflicts.append({"item": item, "reviewer": reviewer, "labels": sorted(found)})
                continue
            out.setdefault(item, {})[reviewer] = next(iter(found))
    return {"labels": out, "ignored": ignored, "conflicts": conflicts}


def assignment(items: dict[str, str], keys: set[str], per_item: int) -> dict[str, list[str]]:
    """``{item: [reviewer, ...]}``: *per_item* reviewers per item, reproducibly."""
    if per_item < 1:
        raise ValueError("--per-item is at least 1")
    out = {}
    for item, digest in sorted(items.items()):
        order = sorted(keys, key=lambda k: hashlib.sha256(f"{digest}\n{k}".encode()).hexdigest())
        out[item] = order[:per_item]
    return out


def queue(repo: Any, rubric: str, items: dict[str, str], per_item: int) -> dict[str, Any]:
    """Each pinned reviewer's assigned and pending items, and labels outside the assignment."""
    keys, why = reviewers(repo)
    found = labels(repo, rubric, items)
    plan = assignment(items, keys, per_item)
    rows = {k: {"assigned": [], "pending": []} for k in sorted(keys)}
    for item, chosen in plan.items():
        for k in chosen:
            rows[k]["assigned"].append(item)
            if k not in found["labels"].get(item, {}):
                rows[k]["pending"].append(item)
    outside = [{"item": i, "reviewer": r} for i, by in sorted(found["labels"].items())
               for r in sorted(by) if r not in plan.get(i, [])]  # fmt: skip
    short = [i for i, chosen in plan.items() if len(chosen) < per_item]
    return {"reviewers": rows, "unassigned_labels": outside, "short": short,
            "pinned": bool(keys), "why": None if keys else why,
            "conflicts": found["conflicts"], "ignored": found["ignored"]}  # fmt: skip


__all__ = ["CONVENTION", "HOLD", "LabelError", "ROLE", "assignment", "check_claim", "labels",
           "queue", "record", "reviewers", "rubric_digest"]  # fmt: skip
