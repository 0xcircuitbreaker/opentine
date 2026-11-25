"""Weight custody events and model-organism records in the query index (0.72).

* ``weight_custody``: one row per ``opentine.weight-custody/1`` attestation
  (:mod:`opentine._weight_custody`), held or not: the artifact, the event, its
  place in the hash chain, the location and digest (weights are never stored);
* ``organism_records``: one row per ``opentine.organism-tag/1``,
  ``opentine.organism-approval/1`` or ``opentine.organism-untag/1`` attestation
  (:mod:`opentine._organism`);
* ``interp_artifacts`` and ``probe_calibrations`` (0.83): :mod:`opentine._query_interp`.

``signed`` is 1 only when the Ed25519 signature verifies *and* the payload's
``signer`` names the key that signed. Under ``--verify`` a custody row is
``verified`` only for a pinned ``runner`` or ``policy`` signer and an organism row
only for a pinned ``policy``, ``curator`` or ``approver`` signer, never one that
holds ``optimizer``. Rows are derived and non-authoritative: ``tine custody
check`` and ``tine organism status`` decide.
"""

from __future__ import annotations

from typing import Any

from opentine._query_interp import COLUMNS as _INTERP_COLUMNS
from opentine._query_interp import ROLES_FOR as _INTERP_ROLES

COLUMNS: dict[str, tuple[str, ...]] = {
    "weight_custody": ("oid", "target", "signer", "signed", "artifact", "event", "seq", "prev",
                       "location", "digest", "size", "run", "tags", "recorded_at"),
    "organism_records": ("oid", "target", "signer", "signed", "record", "artifact", "run",
                         "at"),
}  # fmt: skip
COLUMNS.update(_INTERP_COLUMNS)  # 0.83: interpretability artifacts and probe calibrations
ROLES_FOR = {"weight_custody": ("runner", "policy"),
             "organism_records": ("policy", "curator", "approver"), **_INTERP_ROLES}  # fmt: skip
_ORGANISM = {"opentine.organism-tag/1": ("tag", "tagged_at"),
             "opentine.organism-approval/1": ("approval", "approved_at"),
             "opentine.organism-untag/1": ("untag", "untagged_at")}  # fmt: skip


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def attestation_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from opentine._query_containment import _signed
    from opentine._weight_custody import CONVENTION

    claim = payload.get("claim")
    convention = claim.get("convention") if isinstance(claim, dict) else None
    if convention != CONVENTION and convention not in _ORGANISM:
        from opentine._query_interp import attestation_rows as interp_rows

        return interp_rows(oid, payload)
    head = {"oid": oid, "target": _text(payload.get("target_id")),
            "signer": _text(payload.get("signer")), "signed": _signed(payload)}  # fmt: skip
    if convention in _ORGANISM:
        record, at = _ORGANISM[convention]
        return {"organism_records": [{**head, "record": record,
                                      "artifact": _text(claim.get("artifact")),
                                      "run": _text(claim.get("run")),
                                      "at": _text(claim.get(at))}]}  # fmt: skip
    tags = claim.get("tags")
    tags = ",".join(t for t in tags if isinstance(t, str)) if isinstance(tags, list) else None
    return {"weight_custody": [{
        **head, "artifact": _text(claim.get("artifact")), "event": _text(claim.get("event")),
        "seq": _int(claim.get("seq")), "prev": _text(claim.get("prev")),
        "location": _text(claim.get("location")), "digest": _text(claim.get("digest")),
        "size": _int(claim.get("size")), "run": _text(claim.get("run")), "tags": tags,
        "recorded_at": _text(claim.get("recorded_at"))}]}  # fmt: skip


__all__ = ["COLUMNS", "ROLES_FOR", "attestation_rows"]
