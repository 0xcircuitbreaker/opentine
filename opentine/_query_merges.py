"""History merge records in the query index (0.69).

``history_merges``: one row per ``opentine.history-merge/1`` attestation
(:mod:`opentine._history_merge_record`), read from the object store like
sabotage task records. ``signed`` is 1 only when the Ed25519 signature
verifies *and* the payload's ``signer`` names the key that signed. Under
``--verify`` a row is ``verified`` only for a pinned ``policy`` signer that
holds no ``optimizer`` role, the rule ``tine merge-history verify`` applies.

Rows are derived and non-authoritative: they show which merges landed, not
whether the merge result is right; ``tine merge-history verify`` re-runs it.
"""

from __future__ import annotations

import json
from typing import Any

from opentine._query_values import text as _text

COLUMNS: dict[str, tuple[str, ...]] = {
    "history_merges": ("oid", "target", "signer", "signed", "ref", "base", "sides",
                       "merged", "conflicts"),
}  # fmt: skip
ROLES_FOR = {"history_merges": ("policy",)}


def merge_row(oid: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    from opentine._history_merge_record import CONVENTION
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    claim = payload.get("claim")
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return None
    result = verify_attestation(payload, trust_embedded=True)
    signed = bool(
        result.ok
        and result.algorithm == "ed25519"
        and used_key_fingerprint(payload.get("signature")) == payload.get("signer")
    )
    sides = claim.get("sides")
    conflicts = claim.get("conflicts")
    return {"oid": oid, "target": _text(payload.get("target_id")),
            "signer": _text(payload.get("signer")), "signed": int(signed),
            "ref": _text(claim.get("target")), "base": _text(claim.get("base")),
            "sides": json.dumps(sides, sort_keys=True) if isinstance(sides, list) else None,
            "merged": _text(claim.get("merged")),
            "conflicts": len(conflicts) if isinstance(conflicts, list) else None}  # fmt: skip


__all__ = ["COLUMNS", "ROLES_FOR", "merge_row"]
