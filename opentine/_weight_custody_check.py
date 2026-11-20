"""Gaps in a weight custody chain, and the load gate for tagged artifacts (0.71).

:func:`chain` re-checks each held event of an artifact: the signature binds the
signer, the claim is an ``opentine.weight-custody/1`` claim for this artifact,
``seq`` counts up from 0 and ``prev`` names the event before. A break is
``fail:custody-chain-broken``.

:func:`check` walks the valid events and reports custody **gaps**
(``fail:custody-gap``): the first event is not ``created``; an artifact is
copied, loaded or exported from a location no event put it at, or with a digest
no event gave it (copied without a copy event); a location used after it was
destroyed; an *observed* location or digest (``--file``) that no event explains.
A load of a ``model-organism`` artifact with no earlier valid approval for that
digest is ``fail:custody-unapproved-load``. A signer the pinned trust bundle does
not give the needed role is ``advisory:custody.signer-unpinned``, which blocks
only with ``--strict``. These are command-level codes, not ``tine verify`` codes.

:func:`decide` is the hook gate (``tine custody gate``): a tool call naming a
location or digest of a ``model-organism`` artifact is denied unless a valid
approval covers the artifact's current digest. It fails closed: an unreadable
payload or custody record denies.
"""

from __future__ import annotations

from typing import Any

from opentine import _containment_records as records
from opentine import _weight_custody as wc

GAP, BROKEN, UNAPPROVED = (
    "fail:custody-gap",
    "fail:custody-chain-broken",
    ("fail:custody-unapproved-load"),
)
UNPINNED = "advisory:custody.signer-unpinned"


def _problems(row: dict[str, Any], artifact: str, seq: int, prev: str | None) -> list[str]:
    claim, out = row["claim"] or {}, []
    if not row["signed"]:
        out.append("the event is not signed by the key its signer field names")
    if claim.get("convention") != wc.CONVENTION or claim.get("artifact") != artifact:
        out.append(f"not an {wc.CONVENTION} claim for {artifact}")
    elif claim.get("event") not in wc.EVENTS or not isinstance(claim.get("location"), str):
        out.append(f"malformed event {claim.get('event')!r}")
    if claim.get("seq") != seq or row["hold_seq"] != seq:
        out.append(f"expected seq {seq}, found {claim.get('seq')!r}")
    if claim.get("prev") != prev:
        out.append("prev does not name the event before (the hash chain is broken)")
    return out


def chain(repo: Any, artifact: str) -> list[dict[str, Any]]:
    """Each held event with ``problems`` and ``verification`` (pinned-role state)."""
    out, prev = [], None
    for seq, row in enumerate(wc.events(repo, artifact)):
        claim = row["claim"] or {}
        role = "policy" if claim.get("event") == "approved" else "runner"
        state = records.role_state(repo, row["signer"], role)
        out.append({**row, "problems": _problems(row, artifact, seq, prev),
                    "verification": state, "role": role})  # fmt: skip
        prev = row["oid"]
    return out


def _finding(code: str, oid: str | None, message: str) -> dict[str, Any]:
    return {"code": code, "record": oid, "message": message}


def _walk(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    where: dict[str, str] = {}  # location -> digest held there
    digests: set[str] = set()
    approved: set[str] = set()
    tagged = False
    for i, row in enumerate(rows):
        oid, claim = row["oid"], row["claim"]
        event, loc, dig = claim["event"], claim["location"], claim.get("digest")
        if i == 0 and event != "created":
            findings.append(_finding(GAP, oid, f"the first event is {event}, not created"))
        if event == "created":
            if i:
                findings.append(_finding(GAP, oid, "a second created event for the artifact"))
            tagged = tagged or wc.MODEL_ORGANISM in (claim.get("tags") or [])
            where[loc] = dig
            digests.add(dig)
        elif event == "approved":
            if row["verification"] == "verified":
                approved.add(dig)
        elif event == "destroyed":
            if loc not in where:
                findings.append(_finding(GAP, oid, f"destroyed at {loc}, where no event put it"))
            where.pop(loc, None)
        elif event == "copied":
            if dig not in digests:
                findings.append(_finding(GAP, oid, f"copied with digest {dig}, which no event "
                                         "gave the artifact"))  # fmt: skip
            where[loc] = dig
            digests.add(dig)
        else:  # loaded, exported
            if where.get(loc) != dig:
                seen = "an unrecorded location" if loc not in where else "another digest"
                findings.append(_finding(GAP, oid, f"{event} from {loc} ({seen}): copied "
                                         "without a copy event"))  # fmt: skip
            if event == "loaded" and tagged and dig not in approved:
                why = "a model-organism artifact was loaded with no earlier approval of its digest"
                findings.append(_finding(UNAPPROVED, oid, why))
    return findings, {"where": where, "digests": digests, "approved": approved, "tagged": tagged}


def check(repo: Any, artifact: str, observed: list[tuple[str, str]] | None = None,
          strict: bool = False) -> dict[str, Any]:  # fmt: skip
    """``{"ok", "artifact", "tagged", "locations", "events", "findings"}``."""
    rows, findings = chain(repo, artifact), []
    if not rows:
        findings.append(_finding(GAP, None, f"no custody events are recorded for {artifact}"))
    for row in rows:
        for problem in row["problems"]:
            findings.append(_finding(BROKEN, row["oid"], problem))
        if not row["problems"] and row["verification"] != "verified":
            findings.append(_finding(UNPINNED, row["oid"], row["verification"]))
    valid = [r for r in rows if not r["problems"]]
    walked, state = _walk(valid)
    findings += walked
    for loc, dig in observed or []:
        if state["where"].get(loc) != dig:
            findings.append(_finding(GAP, None, f"{dig} observed at {loc}: no event explains "
                                     "it (copied without a copy event)"))  # fmt: skip
    events = [{"record": r["oid"], "seq": (r["claim"] or {}).get("seq"),
               "event": (r["claim"] or {}).get("event"), "signer": r["signer"],
               "verification": r["verification"], "location": (r["claim"] or {}).get("location"),
               "digest": (r["claim"] or {}).get("digest")} for r in rows]  # fmt: skip
    blocking = ("fail:", "advisory:") if strict else ("fail:",)
    return {"ok": not any(f["code"].startswith(blocking) for f in findings),
            "artifact": artifact, "strict": strict, "tagged": state["tagged"],
            "locations": dict(sorted(state["where"].items())), "events": events,
            "findings": findings}  # fmt: skip


def _strings(value: Any, out: list[str]) -> list[str]:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            _strings(item, out)
    elif isinstance(value, list):
        for item in value:
            _strings(item, out)
    return out


def decide(repo: Any, tool_input: Any) -> dict[str, Any]:
    """``{"decision": "allow|block", "reason", "artifacts"}`` for one tool call."""
    text = "\n".join(_strings(tool_input, []))
    hits = []
    for name in wc.artifacts(repo):
        rows = [r for r in chain(repo, name) if not r["problems"]]
        _found, state = _walk(rows)
        if not state["tagged"]:
            continue
        marks = [*state["where"], *state["digests"]]
        if any(m and m in text for m in marks):
            current = set(state["where"].values())
            if not current or not current <= state["approved"]:
                hits.append(name)
    if hits:
        reason = ("loading a model-organism artifact needs an approval signed by a pinned "
                  f"policy key: {', '.join(hits)}")  # fmt: skip
        return {"decision": "block", "reason": reason, "artifacts": hits}
    return {"decision": "allow", "reason": "", "artifacts": []}


__all__ = ["BROKEN", "GAP", "UNAPPROVED", "UNPINNED", "chain", "check", "decide"]
