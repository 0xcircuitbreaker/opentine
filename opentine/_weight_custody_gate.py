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

A tag counts only when its signer may record it: once key roles are pinned, a
key without the ``runner``, ``policy`` or ``curator`` role (an optimizer key)
cannot tag; with no pinned bundle every signed tag counts, as in 0.71. A mark
matches a whole token of the tool input (bounded by characters that cannot
continue a path name), so a one-letter location cannot match every call, and a
claim whose location or digest is not a string is skipped on its own.
"""

from __future__ import annotations

import re
from typing import Any

from opentine import _containment_records as records
from opentine import _weight_custody as wc
from opentine import _weight_custody_check as check

SCAN_LIMIT = 10**7
TAG_ROLES = ("runner", "policy", "curator")
_NAME = r"[\w.\-]"


def _well_formed(claim: dict[str, Any]) -> bool:
    digest, tags = claim.get("digest"), claim.get("tags") or []
    texts = isinstance(tags, list) and all(isinstance(t, str) for t in tags)
    return (isinstance(claim.get("artifact"), str) and isinstance(claim.get("location"), str)
            and (digest is None or isinstance(digest, str)) and texts)  # fmt: skip


def _may_tag(repo: Any, signer: Any) -> bool:
    """False only when a pinned bundle gives *signer* none of the tagging roles."""
    states = [records.role_state(repo, signer, role) for role in TAG_ROLES]
    return not all(s.startswith("unverified: the signer") for s in states)


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
        if row["signed"] and isinstance(row["claim"], dict) and _well_formed(row["claim"]):
            out.append({**row["claim"], "_signer": row["signer"]})
    return out


def _tagged(repo: Any, claims: list[dict[str, Any]]) -> dict[str, set[str]]:
    """``{artifact: marks}`` for every artifact holding model-organism bytes."""
    tag = wc.MODEL_ORGANISM
    names = {c["artifact"] for c in claims
             if c.get("event") == "created" and tag in (c.get("tags") or [])
             and _may_tag(repo, c["_signer"])}  # fmt: skip
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
    for name, marks in sorted(_tagged(repo, _scan(repo)).items()):
        if any(_mentions(text, m) for m in marks) and not _approved(repo, name):
            hits.append(name)
    if hits:
        reason = ("loading a model-organism artifact needs an approval signed by a pinned "
                  f"policy key: {', '.join(hits)}")  # fmt: skip
        return {"decision": "block", "reason": reason, "artifacts": hits}
    return {"decision": "allow", "reason": "", "artifacts": []}


def _mentions(text: str, mark: str) -> bool:
    """*mark* appears in *text* as a whole token, not inside a longer name."""
    return re.search(f"(?<!{_NAME}){re.escape(mark)}(?!{_NAME})", text) is not None


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
