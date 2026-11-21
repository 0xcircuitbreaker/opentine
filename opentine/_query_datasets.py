"""Curated dataset versions in the query index (0.75).

* ``dataset_versions``: one row per ``opentine.dataset-version/1`` attestation
  (:mod:`opentine._dataset_claims`), held or not: the name, version, previous
  version, selection, member and excluded counts, the filter mode and
  justification, the members digest, the curator and when;
* ``dataset_members``: one row per (version, member run), with the member's
  content digest, to join with ``runs``;
* ``dataset_tombstones``: one row per ``opentine.dataset-tombstone/1``
  attestation: the dataset, the version that held the run, the run, the
  withdrawal it honours, the curator and when.

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
    "dataset_tombstones": ("oid", "target", "signer", "signed", "dataset", "version", "run",
                           "withdrawal", "curator", "at"),
}  # fmt: skip
ROLES_FOR = {"dataset_versions": ("curator",), "dataset_tombstones": ("curator",)}
TABLES = ("dataset_versions", "dataset_tombstones")


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _tombstone(oid: str, payload: dict[str, Any], claim: dict[str, Any]) -> dict[str, Any]:
    """``signed`` is 1 when the signature holds under the key that signed, that key is
    the claim's ``curator``, the record is on the tombstoned run and the claim is well formed."""
    from opentine._dataset_claims import check_record
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    block, signer = payload.get("signature"), payload.get("signer")
    good = (isinstance(block, dict) and used_key_fingerprint(block) == signer
            and claim.get("curator") == signer and payload.get("target_id") == claim.get("run")
            and not check_record(claim)
            and verify_attestation(payload, trust_embedded=True).ok)  # fmt: skip
    fields = ("dataset", "version", "run", "withdrawal", "curator", "at")
    return {"oid": oid, "target": _text(payload.get("target_id")), "signer": _text(signer),
            "signed": int(good), **{k: _text(claim.get(k)) for k in fields}}  # fmt: skip


def attestation_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from opentine._dataset_claims import TOMBSTONE, VERSION, offline

    claim = payload.get("claim")
    if isinstance(claim, dict) and claim.get("convention") == TOMBSTONE:
        return {"dataset_tombstones": [_tombstone(oid, payload, claim)]}
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
