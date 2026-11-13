"""The pyz's rule for an attestation claim it does not know (0.51, FREEZE ruling (b)).

A self-contained copy of ``opentine._claim_status`` (the pyz imports nothing
from the CLI). The pyz checks the envelope (the signature, unchanged) and
reports a claim it has no granted checker for ``unchecked`` -- never ``pass``
and never ``fail``. No predicate is granted in 0.51 (docs/FREEZE.md).
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
