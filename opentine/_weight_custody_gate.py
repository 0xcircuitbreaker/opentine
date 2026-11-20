"""The load gate for ``model-organism`` weight artifacts (0.71, ``tine custody gate``).

:func:`decide` denies a tool call that names any location or digest a
``model-organism`` artifact was ever recorded with, unless the artifact's held
chain is intact and a counted approval, signed by a pinned ``policy`` key, covers
every digest it currently holds.

The tag is not read from the hold rows alone, which a loop could edit: the gate
also scans every signed ``opentine.weight-custody/1`` attestation in the object
store. A tagged ``created`` event keeps its artifact tagged when its hold row is
dropped, and the tag follows the digest, so recording the same bytes under a new
name (or a new location) does not untag them. Destroy events never remove a
location from what the gate matches. Any doubt denies: a broken chain, a tagged
artifact with no held chain, or an unreadable payload.
"""

from __future__ import annotations

from typing import Any

from opentine import _containment_records as records
from opentine import _weight_custody as wc
from opentine import _weight_custody_check as check

SCAN_LIMIT = 10**7


def _scan(repo: Any) -> list[dict[str, Any]]:
    """Every signed custody claim in the object store, held or not."""
    from opentine.repository._objects import iter_typed_object_oids

    out = []
    for oid in iter_typed_object_oids(repo.path, {"attestation"}, limit=SCAN_LIMIT):
        payload = repo.get(oid).payload()
        claim = payload.get("claim") if isinstance(payload, dict) else None
        if not isinstance(claim, dict) or claim.get("convention") != wc.CONVENTION:
            continue
        row = records.read(repo, oid)
        if row["signed"] and isinstance(row["claim"].get("artifact"), str):
            out.append(row["claim"])
    return out


def _tagged(claims: list[dict[str, Any]]) -> dict[str, set[str]]:
    """``{artifact: marks}`` for every artifact holding model-organism bytes."""
    tag = wc.MODEL_ORGANISM
    names = {c["artifact"] for c in claims
             if c.get("event") == "created" and tag in (c.get("tags") or [])}  # fmt: skip
    digests: set[str] = set()
    while True:
        digests |= {c["digest"] for c in claims if c["artifact"] in names and c.get("digest")}
        more = {c["artifact"] for c in claims if c.get("digest") in digests} - names
        if not more:
            break
        names |= more
    marks: dict[str, set[str]] = {name: set() for name in names}
    for c in claims:
        if c["artifact"] in names:
            marks[c["artifact"]] |= {m for m in (c.get("location"), c.get("digest"))
                                     if isinstance(m, str) and m}  # fmt: skip
    return marks


def _approved(repo: Any, name: str) -> bool:
    rows = check.chain(repo, name)
    if not rows or any(r["problems"] for r in rows):
        return False
    _found, state = check.walk([r for r in rows if check.counts(r)])
    current = set(state["where"].values())
    return bool(current) and None not in current and current <= state["approved"]


def decide(repo: Any, tool_input: Any) -> dict[str, Any]:
    """``{"decision": "allow|block", "reason", "artifacts"}`` for one tool call."""
    text = "\n".join(check_strings(tool_input, []))
    hits = []
    for name, marks in sorted(_tagged(_scan(repo)).items()):
        if any(m in text for m in marks) and not _approved(repo, name):
            hits.append(name)
    if hits:
        reason = ("loading a model-organism artifact needs an approval signed by a pinned "
                  f"policy key: {', '.join(hits)}")  # fmt: skip
        return {"decision": "block", "reason": reason, "artifacts": hits}
    return {"decision": "allow", "reason": "", "artifacts": []}


def check_strings(value: Any, out: list[str]) -> list[str]:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            out.append(str(key))
            check_strings(item, out)
    elif isinstance(value, list):
        for item in value:
            check_strings(item, out)
    return out


__all__ = ["decide"]
