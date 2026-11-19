"""Gate verdict records as backtest trajectories (``tine monitor backtest --repo``, 0.63).

The gate (:mod:`opentine._monitor_gate`) signs and holds an
``opentine.monitor-verdict/1`` attestation for every action that is not
``allow``, and ``tine mcp-proxy --save`` records each ``tools/call`` as a run
step. This module joins the two: every ``tools/call`` step of a recorded run
becomes one backtest step ``{"tool", "input", "reasoning"}`` and, when a held
verdict records that action, its online verdict in the backtest shape
(:mod:`opentine._monitor_backtest`).

Which verdict belongs to a step:

* a step the proxy blocked or relayed as a replacement names its verdict; the
  named verdict is used and must record the step's own action
  (``input_digest`` of the redacted ``method`` and ``params``). When it does
  not (an edited step, or a replacement, whose verdict scored the original
  action), the verdict did not see this input: the online verdict keeps the
  gate's digest, so the backtest counts it as ``input_mismatch`` or, for the
  same monitor, ``not_reproduced`` (never as a match);
* any other step takes the held verdict whose ``input_digest`` is its action
  (an advisory verdict on a forwarded call).

Only verdicts that verify (valid claim, Ed25519 signature by a key in the
owner-pinned ``monitor`` role) are read; the rest are counted in
``unverified_verdicts``. A proxy run carries no reasoning text, so a step's
visibility is ``unavailable``; a verdict that saw reasoning is kept with its
own state and counted as ``visibility_mismatch``. ``allow`` is never recorded,
so a step with no verdict is ``no_online_verdict``. Runs carry no attack
labels; their trajectories are unlabelled.
"""

from __future__ import annotations

from typing import Any

from opentine import _monitor_verdict
from opentine._monitor_audit import _marks
from opentine._monitor_rule import digest, seen
from opentine._monitor_verdict import input_digest


def verdicts(repo: Any) -> tuple[dict[str, dict[str, Any]], int]:
    """``({verdict id: claim}, unverified count)`` over the held verdicts."""
    pinned = _monitor_verdict.monitors(repo)
    found, unverified = {}, 0
    for oid in _monitor_verdict.held(repo):
        row = _monitor_verdict.verify(repo, oid, pinned)
        if row["verification"] == "verified" and not row["problems"]:
            found[oid] = row["claim"]
        else:
            unverified += 1
    return found, unverified


def online(claim: dict[str, Any], step: dict[str, Any], *, matches: bool) -> dict[str, Any]:
    """The backtest decision fields of a gate claim recorded for *step*."""
    state = claim["reasoning"]["state"]
    view_digest = digest(seen(step)) if matches else claim["input_digest"]
    return {"monitor": claim["monitor"]["id"], "monitor_digest": claim["monitor"]["model_digest"],
            "input_digest": view_digest, "reasoning": state, "score": claim["score"],
            "threshold": claim["threshold"], "action": claim["action"]}  # fmt: skip


def _step(raw: Any, claims: dict[str, Any], by_input: dict[str, str]) -> dict[str, Any] | None:
    inputs = raw.inputs if isinstance(raw.inputs, dict) else {}
    if inputs.get("method") != "tools/call" or not isinstance(inputs.get("params"), dict):
        return None
    params = inputs["params"]
    step = {"tool": str(params.get("name", "")), "input": params.get("arguments"),
            "reasoning": "unavailable"}  # fmt: skip
    action = input_digest("tools/call", params)
    kind, named = _marks(raw)
    oid = named if kind is not None and isinstance(named, str) else by_input.get(action)
    claim = claims.get(oid) if oid else None
    if claim is not None:
        # A replacement step relays the alternate, not the action the verdict scored.
        matches = kind != "replace" and claim["input_digest"] == action
        step["verdict"] = online(claim, step, matches=matches)
    return step


def trajectories(repo: Any, runs: list[tuple[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """``(trajectories, unverified verdicts)`` for *runs* (``[(name, Run)]``)."""
    claims, unverified = verdicts(repo)
    by_input = {}
    for oid, claim in sorted(claims.items()):
        by_input.setdefault(claim["input_digest"], oid)
    out = []
    for name, run in runs:
        steps = [s for s in (_step(raw, claims, by_input) for raw in run.steps) if s]
        out.append({"run": name, "steps": steps})
    return out, unverified


__all__ = ["online", "trajectories", "verdicts"]
