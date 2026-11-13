"""What a verifier says about an attestation claim it does not know (0.51, FREEZE ruling (b)).

The adopted freeze ruling (docs/FREEZE.md) lets a new in-toto ``predicateType``
or ``attestation.claim`` schema ride inside a frozen envelope only once the
owner grants it by name. Until a verifier knows a claim, it checks the
envelope (the signature over the canonical bytes, unchanged) and reports the
claim itself ``unchecked`` -- never ``pass`` and never ``fail``. No predicate
is granted in 0.51, so every claim is unchecked here. The pyz
(``opentine/_pyz/_claim.py``) and the TS verifier (``ts/verifier/src/claim.ts``)
carry the same rule and the same empty grant list.
"""

from __future__ import annotations

from typing import Any

#: Predicates granted under the ruling, by name (FREEZE.md "Granted predicates").
GRANTED_PREDICATES: frozenset[str] = frozenset()


def claim_name(claim: Any) -> str | None:
    """The claim's ``predicateType`` (or ``schema``) when it names one."""
    if not isinstance(claim, dict):
        return None
    for key in ("predicateType", "schema"):
        name = claim.get(key)
        if isinstance(name, str) and name:
            return name
    return None


def claim_status(claim: Any) -> dict[str, Any]:
    """``{"status": "unchecked", "reason": ..., "predicate": ...}`` for a claim not granted."""
    name = claim_name(claim)
    if name is None:
        return {"status": "unchecked", "reason": "claim.unnamed", "predicate": None}
    if name in GRANTED_PREDICATES:  # pragma: no cover -- none is granted before a sign-off
        raise NotImplementedError(f"granted predicate {name} has no checker")
    return {"status": "unchecked", "reason": "claim.unknown-predicate", "predicate": name}


__all__ = ["GRANTED_PREDICATES", "claim_name", "claim_status"]
