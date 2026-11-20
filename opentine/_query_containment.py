"""Containment evidence and budget ledgers in the query index (0.69).

* ``sandbox_policies``: one row per ``opentine.sandbox-policy/1`` attestation
  (:mod:`opentine._containment`);
* ``containment_findings``: one row per ``opentine.containment-finding/1``
  attestation (:mod:`opentine._containment_detect`), advisory evidence;
* ``budget_ledger``: one row per ``opentine.budget-ledger/1`` annotation
  (:mod:`opentine._budget_ledger`): spend, policy and flag entries.

``signed`` is 1 only when the Ed25519 signature verifies *and* the payload's
``signer`` names the key that signed. Under ``--verify`` a row is ``verified``
only for a pinned ``runner`` signer (a budget ``policy`` entry: a pinned
``policy`` signer) that holds no ``optimizer`` role. Rows are derived and
non-authoritative: ``tine containment check`` and ``tine budget status`` decide.
"""

from __future__ import annotations

from typing import Any

COLUMNS: dict[str, tuple[str, ...]] = {
    "sandbox_policies": ("oid", "target", "signer", "signed", "policy_digest", "recorded_at"),
    "containment_findings": ("oid", "target", "signer", "signed", "category", "step",
                             "detail", "evidence_digest", "found_at"),
    "budget_ledger": ("oid", "previous", "signer", "signed", "subject", "entry", "run",
                      "cost", "tokens", "code", "at"),
}  # fmt: skip
ROLES_FOR = {"sandbox_policies": ("runner",), "containment_findings": ("runner",),
             "budget_ledger": ("runner", "policy")}  # fmt: skip
TABLES = tuple(COLUMNS)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _num(value: Any) -> float | None:
    ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    return float(value) if ok else None


def _signed(payload: dict[str, Any]) -> int:
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    result = verify_attestation(payload, trust_embedded=True)
    used = used_key_fingerprint(payload.get("signature"))
    return int(bool(result.ok and result.algorithm == "ed25519"
                    and used is not None and used == payload.get("signer")))  # fmt: skip


def attestation_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from opentine._containment import CONVENTION as POLICY
    from opentine._containment_detect import CONVENTION as FINDING

    claim = payload.get("claim")
    if not isinstance(claim, dict) or claim.get("convention") not in (POLICY, FINDING):
        return {}
    head = {"oid": oid, "target": _text(payload.get("target_id")),
            "signer": _text(payload.get("signer")), "signed": _signed(payload)}  # fmt: skip
    if claim["convention"] == POLICY:
        return {
            "sandbox_policies": [
                {
                    **head,
                    "policy_digest": _text(claim.get("policy_digest")),
                    "recorded_at": _text(claim.get("recorded_at")),
                }
            ]
        }
    step = claim.get("step")
    return {"containment_findings": [{
        **head, "category": _text(claim.get("category")),
        "step": step if isinstance(step, int) and not isinstance(step, bool) else None,
        "detail": _text(claim.get("detail")),
        "evidence_digest": _text(claim.get("evidence_digest")),
        "found_at": _text(claim.get("found_at"))}]}  # fmt: skip


def ledger_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from opentine._budget_ledger import CONVENTION

    value = payload.get("value")
    if not isinstance(value, dict) or value.get("convention") != CONVENTION:
        return {}
    cost = value.get("cost") if isinstance(value.get("cost"), dict) else {}
    tokens = _num(cost.get("total_tokens"))
    return {"budget_ledger": [{
        "oid": oid, "previous": _text(payload.get("previous_id")),
        "signer": _text(payload.get("signer")), "signed": _signed(payload),
        "subject": _text(value.get("subject")), "entry": _text(value.get("entry")),
        "run": _text(value.get("run")), "cost": _num(cost.get("total_cost")),
        "tokens": None if tokens is None else int(tokens), "code": _text(value.get("code")),
        "at": _text(value.get("at"))}]}  # fmt: skip


__all__ = ["COLUMNS", "ROLES_FOR", "TABLES", "attestation_rows", "ledger_rows"]
