"""Ingest sampling policies and batches in the query index (0.77).

* ``ingest_policies``: one row per ``opentine.ingest-policy/1`` annotation
  (:mod:`opentine._ingest_policy`), held or not: the stream, rate, seed source,
  whether captured events are scrubbed, the kinds captured and dropped
  (``captures``, ``drops``: comma joined), the policy digest and the signed ``issued_at``;
* ``ingest_batches``: one row per ``opentine.ingest-batch/1`` annotation
  (:mod:`opentine._ingest_batch`): the stream, ``seq``, previous batch, policy
  and its digest, the index range, the counts received, captured and dropped
  (by kind and by rate) and ``at``.

``signed`` is 1 only when the Ed25519 signature verifies under the recorded
``signer`` (the key that signed). Under ``--verify`` a policy row is
``verified`` only for a pinned ``policy`` signer and a batch row only for a
pinned ``runner`` signer, never one that also holds ``optimizer``. Rows are
derived and non-authoritative: ``tine ingest verify`` decides whether a stream
holds together; its failures reach the oversight queue as ``ingest`` items
(:mod:`opentine._ingest_oversight`).
"""

from __future__ import annotations

from typing import Any

from opentine import _query_rl
from opentine._query_values import text as _text

COLUMNS: dict[str, tuple[str, ...]] = {
    "ingest_policies": ("oid", "target", "signer", "signed", "stream", "rate", "seed_source",
                        "redact", "captures", "drops", "policy_digest", "issued_at"),
    "ingest_batches": ("oid", "target", "signer", "signed", "stream", "seq", "previous",
                       "policy", "policy_digest", "first_index", "next_index", "received",
                       "captured", "dropped", "dropped_kind", "dropped_rate", "at"),
}  # fmt: skip
COLUMNS.update(_query_rl.COLUMNS)  # 0.84: sealed segments, audits, provenance
ROLES_FOR = {"ingest_policies": ("policy",), "ingest_batches": ("runner",), **_query_rl.ROLES_FOR}
TABLES = tuple(COLUMNS)


def _int(value: Any) -> int | None:
    return value if type(value) is int else None


def _signed(payload: dict[str, Any]) -> int:
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    block = payload.get("signature")
    if not isinstance(block, dict) or used_key_fingerprint(block) != payload.get("signer"):
        return 0
    result = verify_attestation(payload, trust_embedded=True)
    return int(bool(result.ok and result.algorithm == "ed25519"))


def _kinds(value: Any) -> str | None:
    ok = isinstance(value, list) and all(isinstance(k, str) for k in value)
    return ",".join(value) if ok else None


def _policy(head: dict[str, Any], claim: dict[str, Any]) -> dict[str, Any]:
    from opentine._ingest_policy import digest

    try:
        policy_digest: str | None = digest(claim)
    except Exception:  # noqa: BLE001 - a malformed policy has no digest
        policy_digest = None
    rate = claim.get("rate")
    redact = claim.get("redact")
    return {**head, "stream": _text(claim.get("stream")),
            "rate": float(rate) if type(rate) in (int, float) else None,
            "seed_source": _text(claim.get("seed_source")),
            "redact": int(redact) if isinstance(redact, bool) else None,
            "captures": _kinds(claim.get("capture")), "drops": _kinds(claim.get("drop")),
            "policy_digest": policy_digest, "issued_at": _text(claim.get("issued_at"))}  # fmt: skip


def _batch(head: dict[str, Any], claim: dict[str, Any]) -> dict[str, Any]:
    by = claim.get("dropped_by") if isinstance(claim.get("dropped_by"), dict) else {}
    ints = ("seq", "first_index", "next_index", "received", "captured", "dropped")
    return {**head, "stream": _text(claim.get("stream")), "previous": _text(claim.get("previous")),
            "policy": _text(claim.get("policy")),
            "policy_digest": _text(claim.get("policy_digest")),
            **{k: _int(claim.get(k)) for k in ints},
            "dropped_kind": _int(by.get("kind")), "dropped_rate": _int(by.get("rate")),
            "at": _text(claim.get("at"))}  # fmt: skip


def annotation_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Rows of a budget ledger entry (0.69), an ingest policy or batch (0.77) or segment (0.84)."""
    from opentine._ingest_batch import CONVENTION as BATCH
    from opentine._ingest_policy import CONVENTION as POLICY
    from opentine._query_containment import ledger_rows

    claim = payload.get("value")
    convention = claim.get("convention") if isinstance(claim, dict) else None
    if convention not in (POLICY, BATCH, *_query_rl.conventions()):
        return ledger_rows(oid, payload)
    head = {"oid": oid, "target": _text(payload.get("target_id")),
            "signer": _text(payload.get("signer")), "signed": _signed(payload)}  # fmt: skip
    if convention not in (POLICY, BATCH):
        return _query_rl.annotation_rows(head, claim)
    if convention == POLICY:
        return {"ingest_policies": [_policy(head, claim)]}
    return {"ingest_batches": [_batch(head, claim)]}


__all__ = ["COLUMNS", "ROLES_FOR", "TABLES", "annotation_rows"]
