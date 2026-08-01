"""Stable machine-readable JSON for the read-only ``tine`` commands.

With ``--json`` each command below writes exactly one JSON object to stdout and
nothing else. The rich human rendering is unchanged and stays the default, so
``--json`` is purely additive. These objects are a machine interface: within a
major version fields are added, never renamed or removed, and keys are emitted
sorted so two runs of a command diff cleanly. Every value passes through
``json_safe``, so untrusted recorded content cannot make the output
unserializable. Every object carries ``command``, naming the schema it follows.

A failure that stops the command from producing a result is *not* JSON: a run
``show`` or ``cost`` cannot find, an unreadable key file, or a bad filter prints
a human message and exits non-zero, so a script must check the exit status. A
failure that *is* the result still comes out as the object, with the exit status
following it: ``verify`` emits ``ok: false`` — including for a target it could
not read at all — and exits 1, and ``cost`` emits ``over_budget: true`` and
exits 1.

``tine show RUN --json``
    ``command``  ``"show"``
    ``path``     str — file or repository the run was read from
    ``run``      object — ``id``, ``short_id``, ``status``, ``model``,
                 ``created_at``, ``total_cost``, ``step_count``, ``tags`` (list
                 of str), ``user_prompt``, ``system_prompt``
    ``steps``    array — one object per step in recorded order: ``id``,
                 ``short_id``, ``kind``, ``parent_ids`` (list of str),
                 ``model``, ``cost``, ``duration``, ``timestamp``, ``inputs``,
                 ``outputs``, ``usage``, ``billing``, ``error``, ``tool``

``tine verify RUN --json``
    ``command``    ``"verify"``
    ``path``       str — the target as verify resolved it
    ``ok``         bool — integrity passed and, when checked, the signature too
    ``integrity``  object — ``ok``, ``algorithm``, ``expected``, ``actual``,
                   ``reason``, ``draft``
    ``signature``  object or null — null unless key material,
                   ``--require-signature``, or ``--trust-embedded-key`` armed
                   the check, and also null when integrity failed, because
                   integrity is the gate and verify stops there exactly as the
                   human rendering does; otherwise ``ok``, ``state``,
                   ``algorithm``, ``key_id``, ``signer``, ``signed_at``,
                   ``reason``

``tine ls --json`` and ``tine search QUERY --json``
    ``command``  ``"ls"`` or ``"search"``
    ``query``    str — search only: the joined query string
    ``count``    int — number of entries in ``runs``
    ``runs``     array — legacy index rows, newest first for ``ls``: ``run_id``,
                 ``short_id``, ``status``, ``model``, ``steps``, ``cost``,
                 ``created_at``, ``mtime``, ``format_version``, ``tags`` (list
                 of str), ``file``, ``unreadable``

``tine cost RUN --json``
    ``command``        ``"cost"``
    ``run_id``         str
    ``short_id``       str
    ``total_cost``     float
    ``total_tokens``   int
    ``input_tokens``   int
    ``output_tokens``  int
    ``by_model``       object — model id -> cost
    ``by_kind``        object — step kind -> cost
    ``budget``         object or null — ``max_cost``, ``max_steps``,
                       ``max_duration``, ``max_usage``, ``on_breach``,
                       ``strict_cost``
    ``budget_state``   object or null — the recorded breach state, verbatim
    ``over_budget``    bool — true when ``budget_state`` records a breach, which
                       is also when the command exits 1
    ``pricing``        object — cost completeness: ``complete`` (bool),
                       ``unpriced_steps`` (int), ``unpriced_providers`` (list of
                       str). ``total_cost`` counts only priced steps, so when
                       ``complete`` is false it is a known subtotal and not the
                       bill; a managed-cloud step whose regional rates are not in
                       the signed catalog contributes usage but $0. Reported, not
                       enforced: unpriced steps do not change the exit status. A
                       run recorded before this field existed reports
                       ``{complete: true, unpriced_steps: 0}``, since an absent
                       record is no evidence of an unpriced step.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine._jsonsafe import json_safe
from opentine._runtime_accounting import pricing_summary
from opentine.core import Run, short_id


def emit(payload: dict[str, Any]) -> None:
    """Write one JSON object to stdout.

    Deliberately ``print`` and not the Rich console: machine output must not be
    wrapped, coloured, or have square brackets read as markup.
    """
    print(json.dumps(json_safe(payload), sort_keys=True, indent=2))


def _step(step: Any) -> dict[str, Any]:
    return {
        "id": step.id,
        "short_id": step.short_id,
        "kind": step.kind.value,
        "parent_ids": list(step.parent_ids),
        "model": step.model_info,
        "cost": step.cost,
        "duration": step.duration,
        "timestamp": step.timestamp,
        "inputs": step.inputs,
        "outputs": step.outputs,
        "usage": step.usage,
        "billing": step.billing,
        "error": step.error,
        "tool": step.tool_info,
    }


def emit_show(run: Run, path: str | Path) -> None:
    emit(
        {
            "command": "show",
            "path": str(path),
            "run": {
                "id": run.id,
                "short_id": short_id(run.id),
                "status": run.status.value,
                "model": run.model_info,
                "created_at": run.created_at,
                "total_cost": run.total_cost,
                "step_count": len(run.steps),
                "tags": list(run.tags),
                "user_prompt": run.user_prompt,
                "system_prompt": run.system_prompt,
            },
            "steps": [_step(step) for step in run.steps],
        }
    )


def emit_verify(target: str | Path, integrity: Any, signature: Any) -> None:
    emit(
        {
            "command": "verify",
            "path": str(target),
            "ok": bool(integrity.ok and (signature is None or signature.ok)),
            "integrity": {
                "ok": bool(integrity.ok),
                "algorithm": integrity.algorithm,
                "expected": integrity.expected,
                "actual": integrity.actual,
                "reason": integrity.reason,
                "draft": bool(integrity.draft),
            },
            "signature": None
            if signature is None
            else {
                "ok": bool(signature.ok),
                "state": signature.state,
                "algorithm": signature.algorithm,
                "key_id": signature.key_id,
                "signer": signature.signer,
                "signed_at": signature.signed_at,
                "reason": signature.reason,
            },
        }
    )


def _entry(entry: Any) -> dict[str, Any]:
    return {
        "run_id": entry.run_id,
        "short_id": short_id(entry.run_id),
        "status": entry.status,
        "model": entry.model,
        "steps": entry.steps,
        "cost": entry.cost,
        "created_at": entry.created_at,
        "mtime": entry.mtime,
        "format_version": entry.format_version,
        "tags": list(entry.tags),
        "file": entry.file,
        "unreadable": bool(entry.unreadable),
    }


def emit_entries(command: str, entries: list[Any], *, query: str | None = None) -> None:
    payload: dict[str, Any] = {
        "command": command,
        "count": len(entries),
        "runs": [_entry(entry) for entry in entries],
    }
    if query is not None:
        payload["query"] = query
    emit(payload)


def emit_cost(run: Run) -> bool:
    """Emit the cost object; return whether the run records a budget breach."""
    breakdown = run.cost_breakdown()
    budget = run.budget()
    state = run.metadata.get("budget_state")
    breached = bool(isinstance(state, dict) and state.get("breached"))
    emit(
        {
            "command": "cost",
            "run_id": run.id,
            "short_id": short_id(run.id),
            "total_cost": breakdown.total_cost,
            "total_tokens": breakdown.total_tokens,
            "input_tokens": breakdown.input_tokens,
            "output_tokens": breakdown.output_tokens,
            "by_model": dict(breakdown.by_model),
            "by_kind": dict(breakdown.by_kind),
            "budget": None
            if budget is None
            else {
                "max_cost": budget.max_cost,
                "max_steps": budget.max_steps,
                "max_duration": budget.max_duration,
                "max_usage": budget.max_usage,
                "on_breach": budget.on_breach,
                "strict_cost": budget.strict_cost,
            },
            "budget_state": state if isinstance(state, dict) else None,
            "over_budget": breached,
            "pricing": pricing_summary(run),
        }
    )
    return breached
