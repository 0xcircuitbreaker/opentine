"""The signed record of a history merge: an attestation claim convention (0.69).

A merge of run histories (:mod:`opentine._history_merge`) is recorded as an
existing ``attestation`` (tine-attest/2, Ed25519), no new kind. Its target is a
run (the merged value of the target ref, or ``--subject``) and its claim
follows ``opentine.history-merge/1``::

    {"convention": "opentine.history-merge/1",
     "base": "sha256:…",              # digest of the base snapshot
     "sides": ["sha256:…", "sha256:…"],  # the two side snapshots, sorted
     "merged": "sha256:…",            # the merged snapshot
     "conflicts": [{kind, key, base, sides}, …],
     "target": "heads/main" | null}

:func:`check` answers the ``history-merge.verify`` conformance op
(``vectors/85-history-merge.json``): it re-runs the merge from the three
snapshots and compares digests and conflicts with the claim, then checks the
signature. The ports in the pyz (``_pyz/_histmerge.py``) and the TS verifier
(``histmerge.ts``) answer the same op over the same vectors.
"""

from __future__ import annotations

import re
from typing import Any

from opentine._history_merge import merge

CONVENTION = "opentine.history-merge/1"
CLAIM = ("convention", "base", "sides", "merged", "conflicts", "target")
RUN_RE = re.compile(r"run:sha256:[0-9a-f]{64}")
HEX_RE = re.compile(r"[0-9a-f]{64}")


def claim_for(result: dict[str, Any], target: str | None) -> dict[str, Any]:
    digests = result["digests"]
    return {"convention": CONVENTION, "base": digests["base"], "sides": list(digests["sides"]),
            "merged": digests["merged"], "conflicts": result["conflicts"],
            "target": target}  # fmt: skip


def sign(key: Any, result: dict[str, Any], *, subject: str, target: str | None,
         at: str) -> dict[str, Any]:  # fmt: skip
    """The signed attestation payload for one merge result."""
    from opentine._promote import _who
    from opentine.attest_signing import sign_attestation

    if not RUN_RE.fullmatch(subject):
        raise ValueError("the merge record targets a run (run:sha256:HEX)")
    payload = {"claim": claim_for(result, target), "evidence_ids": [], "signer": _who(key),
               "target_id": subject}  # fmt: skip
    return {**payload, "signature": sign_attestation(payload, key, algorithm="ed25519",
                                                     signed_at=at)}  # fmt: skip


def _signature(record: dict[str, Any], public_key: bytes | None) -> tuple[bool, str]:
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import verify_attestation

    block = record.get("signature")
    if not isinstance(block, dict):
        return False, "unsigned"
    if block.get("alg") != "ed25519":
        return False, "error"
    raw = block.get("public_key")
    if not (isinstance(raw, str) and HEX_RE.fullmatch(raw)):
        return False, "error"
    if key_fingerprint(bytes.fromhex(raw)) != record.get("signer"):
        return False, "mismatch"
    if public_key is None:
        found = verify_attestation(record, trust_embedded=True)
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pinned = Ed25519PublicKey.from_public_bytes(public_key)
        found = verify_attestation(record, public_key=pinned)
    return bool(found.ok), str(found.state)


def check(record: Any, base: Any, ours: Any, theirs: Any,
          public_key: bytes | None = None) -> dict[str, Any]:  # fmt: skip
    """``{"ok", "signature", "merged", "merged_matches", "conflicts_match", "conflicts"}``."""
    claim = record.get("claim") if isinstance(record, dict) else None
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        raise ValueError("history-merge.malformed: not an opentine.history-merge/1 claim")
    if set(claim) != set(CLAIM) or not isinstance(claim["conflicts"], list):
        raise ValueError("history-merge.malformed: the claim has exactly " + ", ".join(CLAIM))
    target = record.get("target_id")
    if not (isinstance(target, str) and RUN_RE.fullmatch(target)):
        raise ValueError("history-merge.malformed: the record targets a run")
    result = merge(base, ours, theirs)
    digests = result["digests"]
    merged_ok = (claim["merged"] == digests["merged"] and claim["base"] == digests["base"]
                 and claim["sides"] == digests["sides"])  # fmt: skip
    conflicts_ok = claim["conflicts"] == result["conflicts"]
    signed, state = _signature(record, public_key)
    return {"ok": bool(signed and merged_ok and conflicts_ok), "signature": state,
            "merged": digests["merged"], "merged_matches": merged_ok,
            "conflicts_match": conflicts_ok, "conflicts": len(result["conflicts"])}  # fmt: skip


__all__ = ["CLAIM", "CONVENTION", "check", "claim_for", "sign"]
