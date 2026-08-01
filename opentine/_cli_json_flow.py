"""Stable machine-readable JSON for the ``tine`` commands that *act* on a run.

The contract is the one documented in :mod:`opentine._cli_json`, extended by
reference rather than restated: one JSON object on stdout and nothing else,
keys sorted, every value through ``json_safe``, a ``command`` field naming the
schema, and fields added but never renamed or removed within a major version.
This module writes through that module's single ``emit``, so there is exactly
one JSON writer in the CLI.

One rule from there decides the shape of everything below, so it is worth
restating where it lands: *a failure that is the result comes out as the
object; a failure that stops the command from producing a result does not*.
``tine verify`` emits ``ok: false`` even for a target it could not read,
because reading it **was** the check. ``tine replay --verify`` is not that: a
source that does not load, a step reference that does not resolve, or a harness
that will not start produces no replay and therefore no comparison — those
print a human message and exit 1. Every object this module writes describes a
comparison that completed.

``tine replay RUN --verify --json``
    ``command``            ``"replay-verify"``
    ``ok``                 bool — reproduced; the command exits 0 iff this is
                           true, and it is what ``--ignore-cost-drift``
                           changes (accounting-only drift stops failing)
    ``mode``               str — ``"cache"`` (recorded steps reused) or
                           ``"rerun"`` (``--harness`` executed twice)
    ``path``               str — the source as replay resolved it
    ``run_id``             str — the source run
    ``short_id``           str
    ``replay_id``          str — id of the replay that was saved and read back
    ``second_id``          str — id of the independent second derivation
    ``identity_ok``        bool — cache: the two derivations minted the same
                           64-hex id; rerun: two distinct 64-hex ids
    ``fork_point``         str or null — null in ``rerun`` mode
    ``expected_steps``     int or null — size of the retained closure
                           ``Run.fork`` keeps, as ``--inspect`` previews it
    ``reused_steps``       int or null — steps in the reloaded replay
    ``slice_ok``           bool or null — the two agree
    ``integrity``          object — of the reloaded replay: ``ok``,
                           ``algorithm``, ``expected``, ``actual``, ``reason``,
                           ``draft``
    ``structural_drift``   array of str — ``"<step short id> <field>"``, plus
                           ``"<step short id> missing"``/``"... added"``; any
                           entry fails the check
    ``accounting_drift``   array of str — cost/usage/billing deltas only
    ``ignore_cost_drift``  bool — whether ``--ignore-cost-drift`` was passed
"""

from __future__ import annotations

from typing import Any

from opentine._cli_json import emit
from opentine.core import short_id


def emit_replay_verify(verdict: Any) -> None:
    """Write the one object describing a completed replay comparison."""
    integrity = verdict.integrity
    emit(
        {
            "command": "replay-verify",
            "ok": verdict.reproduced,
            "mode": verdict.mode,
            "path": verdict.path,
            "run_id": verdict.run_id,
            "short_id": short_id(verdict.run_id),
            "replay_id": verdict.replay_id,
            "second_id": verdict.second_id,
            "identity_ok": bool(verdict.identity_ok),
            "fork_point": verdict.fork_point,
            "expected_steps": verdict.expected_steps,
            "reused_steps": verdict.reused_steps,
            "slice_ok": verdict.slice_ok,
            "integrity": {
                "ok": bool(integrity.ok),
                "algorithm": integrity.algorithm,
                "expected": integrity.expected,
                "actual": integrity.actual,
                "reason": integrity.reason,
                "draft": bool(integrity.draft),
            },
            "structural_drift": list(verdict.structural),
            "accounting_drift": list(verdict.accounting),
            "ignore_cost_drift": bool(verdict.ignore_cost_drift),
        }
    )
