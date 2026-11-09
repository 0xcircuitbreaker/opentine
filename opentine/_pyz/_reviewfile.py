"""``tine-verify.pyz FILE`` for a review bundle (0.47, SPEC 4.20).

A JSON file holding one ``opentine.review-bundle`` (``tine review export``
writes it). It passes when every version is reviewer-signed and chained
(``--pubkey`` pins the first reviewer) and every gate decision is signed by a
reviewer of the version it names; each decision gets its own check row, so a
report lists every gate decision it verified. The Review's gate status
(``approved``, ``rejected`` or ``pending``) is reported, not the verdict: a
verified, pending Review passes verification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import _review
from ._artifact import check as row
from ._gitobj import Refused

KIND = "opentine.review-bundle"


def is_bundle(path: Path) -> bool:
    if path.suffix != ".json" or not path.is_file() or path.stat().st_size > 64 << 20:
        return False
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError, RecursionError):
        return False
    return isinstance(value, dict) and value.get("kind") == KIND


def verify(path: Path, public_key: bytes | None) -> list[dict[str, Any]]:
    """The check rows for the review bundle at *path*."""
    value = json.loads(path.read_text("utf-8"))
    pin = public_key.hex() if public_key is not None else None
    try:
        found = bundle_verify(value, pin)
    except Refused as exc:
        return [row("review", "fail", exc.code, str(exc))]
    rows = [row("review", "pass", "review.verified", KIND, **found)]
    by_digest = {_review.digest(v): v for v in value["versions"]}
    for record in value["decisions"]:
        decided = _review.gate_verify(record, by_digest[record["review"]])
        where = "on the head version" if record["review"] == found["head"] else "on an earlier one"
        rows.append(row("review-gate", "pass", "review-gate.verified", where, **decided))
    return rows


def bundle_verify(value: Any, reviewer_key: str | None = None) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "bundle_version", "versions", "decisions"}
        or value["kind"] != "opentine.review-bundle"
        or value["bundle_version"] != 1
        or isinstance(value["bundle_version"], bool)
        or not isinstance(value["decisions"], list)
        or len(value["decisions"]) > 10_000
    ):
        raise _review.bad("not a review bundle")
    versions = value["versions"]
    if not isinstance(versions, list) or not 1 <= len(versions) <= 10_000:
        raise _review.bad("not a history")
    first = last = _review.review_verify(versions[0], reviewer_key=reviewer_key)
    if first["seq"] != 0:
        raise Refused("review.chain-break", "the history does not start at seq 0")
    for previous, record in zip(versions, versions[1:]):
        last = _review.review_verify(record, previous)
    by_digest = {_review.digest(v): v for v in versions}
    gates = {gate: "pending" for gate in versions[-1]["gates"]}
    for record in value["decisions"]:
        named = _review.gate_body(record)["review"]
        if named not in by_digest:
            raise Refused("review-gate.wrong-review", "the decision names no version here")
        found = _review.gate_verify(record, by_digest[named])
        if named == last["digest"] and gates.get(found["gate"]) != "rejected":
            gates[found["gate"]] = "rejected" if found["decision"] == "reject" else "approved"
    states = set(gates.values())
    status = "approved" if gates and states == {"approved"} else "pending"
    return {"review_id": first["review_id"], "head": last["digest"], "seq": last["seq"],
            "versions": len(versions), "state": first["state"],
            "decisions": len(value["decisions"]), "gates": gates,
            "status": "rejected" if "rejected" in states else status}  # fmt: skip


__all__ = ["bundle_verify", "is_bundle", "verify"]
