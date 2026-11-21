"""Policy admissions in the query index (0.75).

``policy_admissions``: one row per ``opentine.policy-admission/1`` attestation
(:mod:`opentine._policy_record`), held or not: the run it targets, the run its
claim names, the decision, the policy name and digest, the input digest and the
self-claimed time.

``signed`` is 1 only when the Ed25519 signature verifies *and* the payload's
``signer`` names the key that signed. Under ``--verify`` a row is ``verified``
only for a pinned ``policy`` signer that does not hold ``optimizer``. Rows are
derived and non-authoritative: ``tine policy show RUN --policy P`` decides
whether a run is admitted.
"""

from __future__ import annotations

from typing import Any

COLUMNS: dict[str, tuple[str, ...]] = {
    "policy_admissions": ("oid", "target", "signer", "signed", "subject", "decision", "policy",
                          "policy_digest", "input_digest", "at"),
}  # fmt: skip
ROLES_FOR = {"policy_admissions": ("policy",)}
TABLES = ("policy_admissions",)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def attestation_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from opentine._policy_record import CONVENTION
    from opentine._query_containment import _signed

    claim = payload.get("claim")
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return {}
    pol = claim.get("policy") if isinstance(claim.get("policy"), dict) else {}
    row = {"oid": oid, "target": _text(payload.get("target_id")),
           "signer": _text(payload.get("signer")), "signed": _signed(payload),
           "subject": _text(claim.get("subject")), "decision": _text(claim.get("decision")),
           "policy": _text(pol.get("name")), "policy_digest": _text(pol.get("digest")),
           "input_digest": _text(claim.get("input_digest")),
           "at": _text(claim.get("at"))}  # fmt: skip
    return {"policy_admissions": [row]}


__all__ = ["COLUMNS", "ROLES_FOR", "TABLES", "attestation_rows"]
