"""What landing a merge-queue entry writes, before the queue's commit CAS (0.47).

:func:`prepare` decides the first entry's fate against the queue's ``head``
and gate policy, and writes every object the landing will reference: the
merged run (:func:`opentine.repository._merge_ops.merge_runs`, no ref moved)
and the signed ``opentine.merge`` attestation (a JSON blob). A queue never
fast-forwards a non-empty target: a candidate that already contains the head
is still merged onto it (``parents`` ``[head, candidate]``), so the first-parent
walk of the target is exactly the landing order and every landing is attested. Nothing here is
reachable until :func:`opentine.coord._merge_queue.land` commits it, and a
merge is deterministic, so a holder killed half-way leaves only objects the
next holder rewrites identically.
"""

from __future__ import annotations

from typing import Any

from opentine.kernel import canonical_json


def _contains(repo: Any, outer: str, inner: str) -> bool:
    """Whether run *outer* holds every event of run *inner*."""
    events = set(repo.get(outer).payload().get("events") or [])
    return set(repo.get(inner).payload().get("events") or []) <= events


def _rejected(run: str, reason: str, fencing: int) -> dict[str, Any]:
    return {"status": "rejected", "run": run, "reason": reason, "merge": None,
            "fencing": fencing, "attestation": None, "gates": []}  # fmt: skip


def prepare(
    repo: Any, value: dict[str, Any], evidence: Any, *, key: Any, algorithm: str, actor: str,
    merged_at: str | None,
) -> dict[str, Any]:  # fmt: skip
    from opentine import _merge_record
    from opentine._merge_gates import evaluate
    from opentine.repository._merge_ops import merge_runs

    run, head, fencing = value["entries"][0]["run"], value["head"], value["fencing"]
    gates: list[dict[str, str]] = []
    if value.get("gates"):
        verdict = evaluate(value["gates"], evidence, run, value["target"])
        if not verdict["ok"]:
            return _rejected(run, "gates: " + "; ".join(verdict["failures"]), fencing)
        gates = verdict["gates"]
    if head is None:
        merged, parents = run, None  # an empty target: nothing to combine
    elif _contains(repo, head, run):
        return _rejected(run, "up-to-date: the target already holds this run", fencing)
    else:
        result = merge_runs(repo, head, run)
        if result["conflicts"]:
            return _rejected(run, f"conflict: {len(result['conflicts'])} conflicts", fencing)
        merged, parents = result["run"], result["parents"]
    attestation = None
    if parents is not None and key is not None:
        record = _merge_record.build(merged, parents, actor=actor, target=value["target"],
                                     fencing=fencing, gates=gates, merged_at=merged_at)  # fmt: skip
        signed = _merge_record.sign(record, key, algorithm=algorithm, key_id=actor,
                                    signed_at=record["merged_at"])  # fmt: skip
        attestation = repo.put("blob", canonical_json(signed), redact=False)
    return {"status": "landed", "run": run, "merge": merged, "parents": parents,
            "fencing": fencing, "attestation": attestation, "gates": gates,
            "fast_forward": parents is None}  # fmt: skip


__all__ = ["prepare"]
