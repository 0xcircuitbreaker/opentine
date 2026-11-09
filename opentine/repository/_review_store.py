"""A repository's Reviews: ``.tine/reviews/<review_id>.json`` (0.47, SPEC 4.19).

Each file is the Review's bundle (``opentine.review-bundle``): every version,
oldest first, and every gate decision, exactly as their reviewers signed them.
:func:`append` and :func:`decide` check the new record against the stored
chain (``opentine._review.check`` / ``check_gate``) before the file is
replaced atomically; nothing here signs. A Review spans repositories by name
(its ``repos``), so it lives beside whichever run repository wrote it and moves
as a bundle (``tine review export``) or through a remote's ``caps.reviews``.
"""

from __future__ import annotations

import json
from typing import Any

from opentine import _review
from opentine._review_rules import ID
from opentine.kernel import canonical_json
from opentine.repository._paths import atomic_bytes, internal_path

DIR = "reviews"
MAX_BYTES = 64 << 20


def _path(repo: Any, review_id: str):
    if not ID.fullmatch(review_id):
        raise ValueError("a review id is [a-z0-9][a-z0-9._-]{0,63}")
    return internal_path(repo.path, DIR, f"{review_id}.json")


def load(repo: Any, review_id: str) -> dict[str, Any] | None:
    """The stored bundle, or ``None`` when there is no such Review."""
    try:
        raw = _path(repo, review_id).read_bytes()
    except FileNotFoundError:
        return None
    if len(raw) > MAX_BYTES:
        raise ValueError(f"review {review_id} exceeds its size limit")
    return json.loads(raw)


def names(repo: Any) -> list[str]:
    folder = internal_path(repo.path, DIR)
    if not folder.is_dir():
        return []
    return sorted(p.stem for p in folder.iterdir() if p.suffix == ".json" and ID.fullmatch(p.stem))


def _save(repo: Any, review_id: str, value: dict[str, Any]) -> None:
    path = _path(repo, review_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(path, canonical_json(value))


def append(repo: Any, record: dict[str, Any], *, expected: str | None = None) -> str:
    """Store *record* as the next version of its Review; return its digest.

    *expected* is the head the caller built on: a Review that moved meanwhile
    is refused rather than forked.
    """
    review_id = str(record.get("review_id"))
    current = load(repo, review_id)
    versions = [] if current is None else current["versions"]
    head = _review.digest(versions[-1]) if versions else None
    if head != expected:
        raise ValueError(f"review {review_id} moved meanwhile: show it and retry")
    _review.check(record, previous=versions[-1] if versions else None)
    if not versions and record["seq"] != 0:
        raise ValueError("the first version of a review is seq 0")
    decisions = [] if current is None else current["decisions"]
    _save(repo, review_id, _review.bundle([*versions, record], decisions))
    return _review.digest(record)


def decide(repo: Any, record: dict[str, Any]) -> dict[str, Any]:
    """Store a gate decision on a version of its Review (``check_gate`` first)."""
    review_id = str(record.get("review_id"))
    current = load(repo, review_id)
    if current is None:
        raise KeyError(f"no review {review_id} here")
    by_digest = {_review.digest(v): v for v in current["versions"]}
    version = by_digest.get(record.get("review"))
    if version is None:
        from opentine._signed_record import RecordError

        raise RecordError("review-gate.wrong-review", "the decision names no version of it")
    found = _review.check_gate(record, version)
    decisions = [*current["decisions"], record]
    _save(repo, review_id, _review.bundle(current["versions"], decisions))
    return found


def install(repo: Any, value: dict[str, Any]) -> dict[str, int]:
    """Adopt a verified bundle that extends this repository's copy of the Review."""
    _review.verify_bundle(value)
    review_id = value["versions"][0]["review_id"]
    current = load(repo, review_id)
    ours = [] if current is None else [_review.digest(v) for v in current["versions"]]
    theirs = [_review.digest(v) for v in value["versions"]]
    common = min(len(ours), len(theirs))
    if ours[:common] != theirs[:common]:
        raise ValueError(f"the imported review {review_id} forks from the local one")
    versions = value["versions"] if len(theirs) >= len(ours) else current["versions"]  # type: ignore[index]
    known = set() if current is None else {_review.digest(d) for d in current["decisions"]}
    fresh = [d for d in value["decisions"] if _review.digest(d) not in known]
    decisions = [*([] if current is None else current["decisions"]), *fresh]
    _save(repo, review_id, _review.bundle(versions, decisions))
    return {"versions": max(0, len(theirs) - len(ours)), "decisions": len(fresh)}


__all__ = ["DIR", "append", "decide", "install", "load", "names"]
