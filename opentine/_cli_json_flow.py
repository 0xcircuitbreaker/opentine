"""Stable machine-readable JSON for the ``tine`` commands that *compare* runs.

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

Both comparison commands publish **one** drift object, built here by
``drift_payload`` out of ``classify_drift`` over the buckets ``_graph_diff``
already reports, so a consumer parses the same four keys either way and a new
bucket appears in both surfaces at once:

    ``structural``   array of str — ``"<step short id> <field>"`` for every
                     non-accounting delta, plus ``"<step short id> missing"``
                     and ``"... added"`` for a step on one side only; any entry
                     means the two runs are not the same run
    ``accounting``   array of str — cost/usage/billing deltas only, the ones
                     ``--ignore-cost-drift`` is allowed to forgive
    ``only_source``  array of str — short ids present only on the left (the
                     source run, or the second derivation under ``--verify``)
    ``only_replay``  array of str — short ids present only on the right (the
                     run compared against it, or the reloaded replay)

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
    ``drift``              object — the four shared buckets above
    ``structural_drift``   array of str — ``drift.structural``, kept flat at the
                           top level because it shipped that way
    ``accounting_drift``   array of str — ``drift.accounting``, likewise
    ``ignore_cost_drift``  bool — whether ``--ignore-cost-drift`` was passed

``tine diff RUN_A RUN_B --json``
    ``command``          ``"diff"``
    ``left``             object — ``run_id``, ``short_id``, ``path``
    ``right``            object — the same three fields for the second run
    ``common_ancestor``  str or null — full step id of the newest step both
                         tips descend from, null when the runs share no history
    ``identical``        bool — no bucket of ``drift`` carries an entry; this is
                         exactly the ``--exit-code`` predicate
    ``drift``            object — the four shared buckets above, byte-for-byte
                         the shape ``replay --verify --json`` publishes
"""

from __future__ import annotations

from typing import Any

from opentine._cli_json import emit
from opentine.core import Run, short_id

#: Exactly the deltas ``_graph_diff._drift`` reports; everything ``_fields`` adds
#: on top is structural. A guard test pins the split against that function.
ACCOUNTING_FIELDS = frozenset({"billing", "cost", "usage"})


def classify_drift(diff: Any) -> tuple[list[str], list[str]]:
    """Split one ``RunDiff`` into (structural, accounting) labels."""
    structural: list[str] = []
    accounting: list[str] = []
    for change in diff.changed:
        label = short_id(change.step_a.id)
        for delta in change.fields:
            bucket = accounting if delta.name in ACCOUNTING_FIELDS else structural
            bucket.append(f"{label} {delta.name}")
    structural.extend(f"{short_id(step.id)} missing" for step in diff.only_a)
    structural.extend(f"{short_id(step.id)} added" for step in diff.only_b)
    return sorted(structural), sorted(accounting)


def drift_payload(diff: Any) -> dict[str, list[str]]:
    """The one drift object, so the two comparison commands cannot disagree."""
    structural, accounting = classify_drift(diff)
    return {
        "structural": structural,
        "accounting": accounting,
        "only_source": sorted(short_id(step.id) for step in diff.only_a),
        "only_replay": sorted(short_id(step.id) for step in diff.only_b),
    }


def identical(drift: dict[str, list[str]]) -> bool:
    """No bucket carries an entry — the ``--exit-code`` predicate, spelled once."""
    return not any(drift.values())


def _side(run: Run, path: Any) -> dict[str, Any]:
    return {"run_id": run.id, "short_id": short_id(run.id), "path": str(path)}


def emit_diff(left: Run, right: Run, paths: tuple[Any, Any], diff: Any) -> bool:
    """Write the object describing one legacy comparison; return ``identical``."""
    drift = drift_payload(diff)
    same = identical(drift)
    emit(
        {
            "command": "diff",
            "left": _side(left, paths[0]),
            "right": _side(right, paths[1]),
            "common_ancestor": diff.common_ancestor,
            "identical": same,
            "drift": drift,
        }
    )
    return same


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
            "drift": dict(verdict.drift),
            "structural_drift": list(verdict.structural),
            "accounting_drift": list(verdict.accounting),
            "ignore_cost_drift": bool(verdict.ignore_cost_drift),
        }
    )
