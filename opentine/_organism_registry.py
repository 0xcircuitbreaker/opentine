"""Reading the model-organism registry (0.72): held tags, untags, approvals, accesses.

The registry is the set of held ``organism:`` records (:mod:`opentine._organism`).
:func:`registry` raises :class:`RegistryUnreadable` when the holds file or a
held tag or untag record cannot be read, so a gate refuses (fail closed)
instead of treating an unreadable registry as "nothing is tagged".
"""

from __future__ import annotations

import json
from typing import Any

from opentine import _containment_records as records
from opentine._organism import (
    ACCESS,
    APPROVAL,
    BANNED_APPROVER,
    DIGEST_RE,
    HOLD,
    TAG,
    TAG_ROLES,
    UNTAG,
    OrganismError,
    hold_target,
    item,
    verification,
)
from opentine.kernel import canonical_json


class RegistryUnreadable(OrganismError):
    """The tag registry cannot be read: every gated call is refused."""


def _held(repo: Any, prefix: str) -> list[tuple[str, dict[str, Any]]]:
    from opentine.repository._holds import HoldError

    try:
        return records.held(repo, prefix)
    except HoldError as exc:
        raise RegistryUnreadable(f"organism.registry-unreadable: {exc}") from exc


def _claims(repo: Any, kind: str, convention: str) -> list[dict[str, Any]]:
    out = []
    for target, row in _held(repo, f"{HOLD}{kind}:"):
        claim = row["claim"]
        if claim is None or claim.get("convention") != convention:
            if kind in ("tag", "untag"):
                raise RegistryUnreadable(f"organism.registry-unreadable: held {kind} record "
                                         f"{row['oid']} ({target}) cannot be read")  # fmt: skip
            continue
        if target != hold_target(kind, str(claim.get("artifact", ""))):
            continue  # a record held under another artifact's name counts for nothing
        out.append(row)
    return out


def _stored_tags(repo: Any, seen: set[str]) -> list[dict[str, Any]]:
    """Tag attestations in the object store whose hold row is gone (dropping it never untags)."""
    out = []
    for oid in repo.iter_oids():
        if not oid.startswith("attestation:") or oid in seen:
            continue
        row = records.read(repo, oid)
        claim = row["claim"]
        if claim and claim.get("convention") == TAG and DIGEST_RE.match(str(claim.get("artifact"))):
            out.append(row)
    return out


def oversight_state(repo: Any, tag_record: str) -> str:
    """The k-of-n oversight state of untagging *tag_record* (``unrouted`` grants nothing)."""
    from opentine import _oversight, _oversight_policy
    from opentine._oversight_gate import tally

    try:
        state = _oversight_policy.load(repo.path)
    except _oversight_policy.OversightError:
        return "unreadable"
    if state["policy"] is None:
        return "unrouted"
    tiers = _oversight_policy.route(state["policy"], {"source": "organism", "label": None})
    rows = _oversight.by_objects(repo).get(item(tag_record), [])
    return tally(state, tiers, rows)["state"]


def registry(repo: Any) -> dict[str, dict[str, Any]]:
    """``{artifact: {"tagged", "live", "names", "tags", "untags"}}`` for every tagged artifact."""
    out: dict[str, dict[str, Any]] = {}
    held_tags = _claims(repo, "tag", TAG)
    for row in held_tags + _stored_tags(repo, {r["oid"] for r in held_tags}):
        claim = row["claim"]
        entry = out.setdefault(claim["artifact"], {"tags": [], "untags": []})
        names = claim.get("names") if isinstance(claim.get("names"), list) else []
        entry["tags"].append({"record": row["oid"], "signer": row["signer"],
                              "verification": verification(repo, row, TAG_ROLES),
                              "names": [n for n in names if isinstance(n, str)],
                              "reason": str(claim.get("reason", "")),
                              "tagged_at": claim.get("tagged_at"),
                              "released_by": None})  # fmt: skip
    for row in _claims(repo, "untag", UNTAG):
        claim, entry = row["claim"], out.get(row["claim"]["artifact"])
        if entry is None:
            continue
        releases = claim.get("releases") if isinstance(claim.get("releases"), list) else []
        state = verification(repo, row, TAG_ROLES)
        approved = all(oversight_state(repo, t) == "approved" for t in releases)
        effective = state == "verified" and approved and bool(releases)
        entry["untags"].append({"record": row["oid"], "releases": releases,
                                "verification": state, "effective": effective})  # fmt: skip
        for t in entry["tags"] if effective else []:
            if t["record"] in releases:
                t["released_by"] = row["oid"]
    for entry in out.values():
        entry["live"] = sorted(t["record"] for t in entry["tags"] if t["released_by"] is None)
        entry["tagged"] = bool(entry["live"])
        entry["names"] = sorted({n for t in entry["tags"] if t["released_by"] is None
                                 for n in t["names"]})  # fmt: skip
    return out


def approvals(repo: Any, artifact: str) -> list[dict[str, Any]]:
    out = []
    for row in _claims(repo, "approval", APPROVAL):
        claim = row["claim"]
        if claim.get("artifact") != artifact:
            continue
        state = verification(repo, row, ("approver",), BANNED_APPROVER)
        out.append({"record": row["oid"], "run": claim.get("run"), "signer": row["signer"],
                    "why": str(claim.get("why", "")), "approved_at": claim.get("approved_at"),
                    "verification": state, "valid": state == "verified"})  # fmt: skip
    return out


def approval_for(repo: Any, artifact: str, run: str) -> str | None:
    """A valid approval record binding *artifact* to *run*, or ``None``."""
    hits = [a["record"] for a in approvals(repo, artifact) if a["valid"] and a["run"] == run]
    return sorted(hits)[0] if hits else None


def log_access(repo: Any, entry: dict[str, Any]) -> str:
    """Store and hold one access-log entry; its blob id."""
    from opentine.repository._holds import edit_holds, holds_path
    from opentine.repository._link_touch import touch_links

    oid = repo.put("blob", canonical_json({"convention": ACCESS, **entry}), redact=False)
    touch_links(repo, [oid])
    row = {"oid": oid, "target": hold_target("access", entry["artifact"])}
    edit_holds(holds_path(repo), lambda rows: [*(r for r in rows if r != row), row])
    return oid


def accesses(repo: Any, artifact: str) -> list[dict[str, Any]]:
    from opentine.repository._holds import HoldError, holds_path, read_holds

    try:
        rows = read_holds(holds_path(repo))
    except HoldError as exc:
        raise RegistryUnreadable(f"organism.registry-unreadable: {exc}") from exc
    out = []
    for r in rows:
        if r["target"] != hold_target("access", artifact):
            continue
        try:
            doc = json.loads(bytes(repo.get(r["oid"]).body))
        except Exception:  # noqa: BLE001 - an unreadable entry is listed as such
            doc = {}
        doc = doc if isinstance(doc, dict) else {}
        out.append({"id": r["oid"], "run": doc.get("run"), "outcome": doc.get("outcome"),
                    "tool": doc.get("tool"), "approval": doc.get("approval"),
                    "at": doc.get("at")})  # fmt: skip
    return sorted(out, key=lambda a: (str(a["at"] or ""), a["id"]))


__all__ = ["RegistryUnreadable", "accesses", "approval_for", "approvals", "log_access",
           "oversight_state", "registry"]  # fmt: skip
