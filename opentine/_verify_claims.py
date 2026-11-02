"""Claim-to-tool-output cross-check for ``tine verify --offline``.

A stored ``tine-actions/1`` manifest *claims* what the agent did: one entry per
tool call, each naming a ``step_id`` and a ``digest`` of the action record.
This check holds every claim against the recorded run:

* the entry's ``step_id`` must be a recorded **tool** step (``claims.no-tool-step``);
* that step must still hash to its id -- the id covers the step's inputs *and*
  outputs, so this is what binds a claim to the tool output actually recorded
  (``claims.output-mismatch``); a step carrying a ``[REDACTED`` marker cannot be
  rehashed and is reported in the detail, not blamed;
* an entry that carries an ``output_digest`` (SHA-256 of the canonical step
  ``outputs``) must match the recorded outputs (``claims.output-mismatch``);
* the entry's action digest must equal the one recomputed from the run
  (``claims.digest-mismatch``), and every recorded tool call must be claimed
  (``claims.unclaimed-step``).

It establishes consistency between two files, not who wrote either: the
manifest's signature is the ``action-manifest`` check's business.
"""

from __future__ import annotations

import hashlib
from typing import Any

from opentine._canon import _canonical_bytes
from opentine._verify_report import INTERNAL_ONLY, Check

_BASIS = f"{INTERNAL_ONLY} (manifest entries against recorded steps)"


def _fail(reason: str, detail: str) -> Check:
    return Check("claims", "fail", reason, detail, _BASIS)


def claims_check(stored: Any, data: Any, run: Any) -> Check:
    from opentine._actions_manifest import build_body
    from opentine._verify_locate import _recomputed

    if stored is None:
        return Check("claims", "not-applicable", "claims.absent", "no action manifest", "none")
    if not isinstance(stored, dict) or not isinstance(stored.get("body"), dict):
        return _fail("claims.unreadable", "action manifest is unreadable or malformed")
    if run is None or not isinstance(data, dict):
        return Check("claims", "not-applicable", "claims.no-run", "run did not load", "none")
    steps = (data.get("graph") or {}).get("steps") or {}
    entries = [e for e in stored["body"].get("entries") or [] if isinstance(e, dict)]
    skipped = 0
    for entry in entries:
        sid, seq = entry.get("step_id"), entry.get("seq")
        step = steps.get(sid) if isinstance(sid, str) else None
        if not isinstance(step, dict) or step.get("kind") != "tool":
            return _fail("claims.no-tool-step", f"entry seq {seq} names no recorded tool step")
        if b"[REDACTED" in _canonical_bytes(step):
            skipped += 1
        elif _recomputed(step) != sid:
            return _fail(
                "claims.output-mismatch",
                f"entry seq {seq}: step {sid} no longer hashes to its id (inputs/outputs edited)",
            )
        claimed = entry.get("output_digest")
        if claimed is not None:
            recorded = hashlib.sha256(_canonical_bytes(step.get("outputs") or {})).hexdigest()
            if claimed != recorded:
                return _fail("claims.output-mismatch", f"entry seq {seq}: output digest differs")
    try:
        fresh = build_body(run)["entries"]
    except Exception:
        return _fail("claims.unrecomputable", "the run's actions cannot be recomputed")
    claimed_by_step = {e.get("step_id"): e.get("digest") for e in entries}
    for entry in fresh:
        if entry["step_id"] not in claimed_by_step:
            return _fail("claims.unclaimed-step", f"tool step {entry['step_id']} is not claimed")
        if claimed_by_step[entry["step_id"]] != entry["digest"]:
            return _fail(
                "claims.digest-mismatch",
                f"entry seq {entry['seq']} (step {entry['step_id']}) differs from the run",
            )
    note = f"; {skipped} redacted step(s) not rehashable" if skipped else ""
    detail = f"{len(entries)} claim(s) map to recorded tool steps{note}"
    return Check("claims", "pass", "claims.match", detail, _BASIS)


__all__ = ["claims_check"]
