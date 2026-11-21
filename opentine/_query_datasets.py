"""Curated dataset versions in the query index (0.75).

* ``dataset_versions``: one row per ``opentine.dataset-version/1`` attestation
  (:mod:`opentine._dataset_claims`), held or not: the name, version, previous
  version, selection, member and excluded counts, the filter mode and
  justification, the members digest, the curator and when;
* ``dataset_members``: one row per (version, member run), with the member's
  content digest, to join with ``runs``.

``signed`` is 1 only when the offline check of the version holds: the Ed25519
signature verifies, the payload ``signer`` is the key that signed and is the
claim's ``curator``, and the claim is well formed (members digest included).
Under ``--verify`` a version row is ``verified`` only for a pinned ``curator``
signer that does not hold ``optimizer``. Rows are derived and
non-authoritative: ``tine dataset versions`` decides.
"""

from __future__ import annotations

from typing import Any

COLUMNS: dict[str, tuple[str, ...]] = {
    "dataset_versions": ("oid", "target", "signer", "signed", "name", "version", "previous",
                         "selection", "members", "excluded", "mode", "justification",
                         "members_digest", "curator", "created_at"),
    "dataset_members": ("oid", "run", "content"),
}  # fmt: skip
ROLES_FOR = {"dataset_versions": ("curator",)}
TABLES = ("dataset_versions",)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def attestation_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from opentine._dataset_claims import VERSION, offline

    claim = payload.get("claim")
    if not isinstance(claim, dict) or claim.get("convention") != VERSION:
        return {}
    check = offline(payload)
    good = not check["problems"]
    flt = claim.get("taint_filter") if good else {}
    version = claim.get("version")
    row = {"oid": oid, "target": _text(payload.get("target_id")),
           "signer": _text(payload.get("signer")), "signed": int(check["ok"]),
           "name": _text(claim.get("name")),
           "version": version if isinstance(version, int) else None,
           "previous": _text(claim.get("previous")), "selection": _text(claim.get("selection")),
           "members": check["members"], "excluded": check["excluded"],
           "mode": _text(flt.get("mode")), "justification": _text(flt.get("justification")),
           "members_digest": _text(claim.get("members_digest")),
           "curator": _text(claim.get("curator")),
           "created_at": _text(claim.get("created_at"))}  # fmt: skip
    members = claim["members"] if good else []
    return {
        "dataset_versions": [row],
        "dataset_members": [{"oid": oid, "run": m["run"], "content": m["content"]}
                            for m in members],
    }  # fmt: skip


__all__ = ["COLUMNS", "ROLES_FOR", "TABLES", "attestation_rows"]
