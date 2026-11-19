"""``tine monitor verify``: every blocked action has a verdict record, offline (0.63).

Reads only the repository and the recorded runs; no monitor is called.

* each held verdict (``monitor-verdict:`` holds) must read as a valid
  ``opentine.monitor-verdict/1`` claim with a good Ed25519 signature
  (``fail:monitor.verdict-invalid``); a signer outside the owner-pinned
  ``monitor`` role is ``advisory:monitor.verdict-unpinned``;
* each step of a given run that the proxy answered with a monitor block (its
  JSON-RPC error carries ``data["opentine.monitor"]``) must name a held,
  enforced, blocking verdict whose ``input_digest`` is the step's own action
  (``fail:monitor.blocked-without-verdict``, ``fail:monitor.verdict-not-held``,
  ``fail:monitor.verdict-mismatch``);
* each step relayed as a replacement (``params._meta["opentine/monitor"]``)
  must name a verdict whose chosen trajectory is that step's action.

Findings are CLI findings (D12: ``fail:`` blocks, ``advisory:`` only with
``--strict``); they are not ``tine verify`` codes.
"""

from __future__ import annotations

from typing import Any

from opentine import _monitor_stop, _monitor_verdict
from opentine._monitor_verdict import META_KEY, input_digest


def _finding(level: str, code: str, message: str, **where: Any) -> dict[str, Any]:
    return {"level": level, "code": f"{level}:{code}", "message": message,
            "verdict": where.get("verdict"), "run": where.get("run"),
            "step": where.get("step")}  # fmt: skip


def _marks(step: Any) -> tuple[str | None, Any]:
    """``("block"|"replace"|None, verdict id)`` for one recorded step."""
    error = step.error if isinstance(step.error, dict) else {}
    data = error.get("data") if isinstance(error.get("data"), dict) else {}
    mark = data.get("opentine.monitor")
    if isinstance(mark, dict):
        return "block", mark.get("verdict")
    params = step.inputs.get("params") if isinstance(step.inputs, dict) else None
    meta = params.get("_meta") if isinstance(params, dict) else None
    mark = meta.get(META_KEY) if isinstance(meta, dict) else None
    if isinstance(mark, dict):
        return "replace", mark.get("verdict")
    return None, None


def _check_step(step: Any, run_id: str, kind: str, oid: Any, rows: dict[str, Any]) -> list:
    where = {"run": run_id, "step": step.id, "verdict": oid if isinstance(oid, str) else None}
    if not isinstance(oid, str) or not oid:
        return [_finding("fail", "monitor.blocked-without-verdict",
                         f"a {kind}ed action names no verdict", **where)]  # fmt: skip
    row = rows.get(oid)
    if row is None:
        return [
            _finding(
                "fail",
                "monitor.verdict-not-held",
                f"the verdict {oid} is not kept by a monitor-verdict hold",
                **where,
            )
        ]
    claim = row["claim"] if isinstance(row["claim"], dict) else {}
    digest = input_digest(str(step.inputs.get("method", "")), step.inputs.get("params"))
    if kind == "block":
        ok = claim.get("enforced") is True and claim.get("input_digest") == digest
    else:
        chosen = [
            t for t in claim.get("trajectories") or [] if t.get("role") == claim.get("chosen")
        ]
        ok = claim.get("enforced") is True and any(t.get("digest") == digest for t in chosen)
    if ok:
        return []
    return [
        _finding(
            "fail",
            "monitor.verdict-mismatch",
            f"the verdict {oid} does not record this {kind}ed action",
            **where,
        )
    ]


def audit(repo: Any, runs: list[tuple[str, Any]]) -> dict[str, Any]:
    """The audit body: counts, stop tokens and findings. *runs* is ``[(name, Run)]``."""
    from opentine.repository._holds import HoldError

    findings: list[dict[str, Any]] = []
    try:
        held = _monitor_verdict.held(repo)
    except HoldError as exc:
        held = []
        findings.append(_finding("fail", "monitor.holds-unreadable", str(exc)))
    pinned = _monitor_verdict.monitors(repo)
    rows = {oid: _monitor_verdict.verify(repo, oid, pinned) for oid in held}
    for oid, row in rows.items():
        state = row["verification"]
        if row["problems"] or not row["signed"]:
            why = row["problems"][0] if row["problems"] else state
            findings.append(_finding("fail", "monitor.verdict-invalid", why, verdict=oid))
        elif state != "verified":
            findings.append(_finding("advisory", "monitor.verdict-unpinned", state, verdict=oid))
    blocked = replaced = 0
    for name, run in runs:
        for step in run.steps:
            kind, oid = _marks(step)
            if kind is None:
                continue
            blocked += kind == "block"
            replaced += kind == "replace"
            findings.extend(_check_step(step, name, kind, oid, rows))
    stops = _monitor_stop.tokens(repo)
    for token in stops:
        if token["verification"] != "verified":
            findings.append(_finding("advisory", "monitor.stop-unverified",
                                     f"stop {token['scope']}: {token['verification']}",
                                     verdict=token["token"]))  # fmt: skip
    return {"verdicts": len(held), "blocked_actions": blocked, "replaced_actions": replaced,
            "runs": [name for name, _ in runs], "stops": stops, "findings": findings}  # fmt: skip


__all__ = ["audit"]
