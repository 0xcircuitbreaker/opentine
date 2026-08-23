"""The per-row object shapes the run views share.

A step and a legacy index entry are rendered by more than one command — ``show``
and ``repo-show`` for a step, ``ls`` and ``search`` for an entry — so their key
sets live in one place and cannot drift apart between commands. The *schema*
(what each key means, and the add-never-rename promise it is under) stays in
:mod:`opentine._cli_json`, which is the module the README points a reader at;
this is only where the two dicts are built.
"""

from __future__ import annotations

from typing import Any

from opentine.core import short_id


def _step(step: Any) -> dict[str, Any]:
    return {
        "id": step.id,
        "short_id": step.short_id,
        "kind": step.kind.value,
        "parent_ids": list(step.parent_ids),
        "provider": step.provider,
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
