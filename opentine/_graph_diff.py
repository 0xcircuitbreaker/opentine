"""Lineage-aware comparison kept separate from mutable run operations."""

from __future__ import annotations

import hashlib
from typing import Any

from opentine._graph_types import FieldDelta, RunDiff, Step, StepChange


def _position_keys(run) -> dict[str, str]:
    children: dict[str | None, list[str]] = {}
    for step_id in run.graph.order:
        step = run.graph.steps[step_id]
        primary = step.parent_ids[0] if step.parent_ids else None
        children.setdefault(primary, []).append(step_id)
    keys: dict[str, str] = {}

    def position(parent: str, index: int) -> str:
        body = f"opentine.graph-position.v1\0{parent}\0{index}".encode()
        return hashlib.sha256(body).hexdigest()

    stack = [
        (root, position("root", index)) for index, root in enumerate(sorted(children.get(None, [])))
    ]
    while stack:
        step_id, key = stack.pop()
        keys[step_id] = key
        for index, child in enumerate(sorted(children.get(step_id, []))):
            stack.append((child, position(key, index)))
    return keys


def _changed_keys(left: Any, right: Any) -> list[str]:
    if isinstance(left, dict) and isinstance(right, dict):
        return sorted(key for key in set(left) | set(right) if left.get(key) != right.get(key))
    return []


def _drift(left: Step, right: Step) -> list[FieldDelta]:
    deltas: list[FieldDelta] = []
    if abs(left.cost - right.cost) > 1e-12:
        deltas.append(FieldDelta("cost", left.cost, right.cost))
    for name in ("usage", "billing"):
        before, after = getattr(left, name), getattr(right, name)
        if before != after:
            deltas.append(FieldDelta(name, before, after, _changed_keys(before, after)))
    return deltas


def _fields(left: Step, right: Step) -> list[FieldDelta]:
    deltas: list[FieldDelta] = []
    for name in ("inputs", "outputs", "model_info", "tool_info", "error"):
        before, after = getattr(left, name), getattr(right, name)
        if before != after:
            deltas.append(FieldDelta(name, before, after, _changed_keys(before, after)))
    return [*deltas, *_drift(left, right)]


def diff_runs(left, right) -> RunDiff:
    left_ids, right_ids = set(left.graph.steps), set(right.graph.steps)
    left_tip = left.refs.get("main") or (left.steps[-1].id if left.steps else "")
    right_tip = right.refs.get("main") or (right.steps[-1].id if right.steps else "")
    common = None
    if left_tip and right_tip:
        left_ancestors = [step.id for step in left.ancestors(left_tip)]
        right_ancestors = {step.id for step in right.ancestors(right_tip)}
        common = next(
            (step_id for step_id in reversed(left_ancestors) if step_id in right_ancestors), None
        )
    left_positions = _position_keys(left)
    right_positions = _position_keys(right)
    right_by_position = {
        (position, str(right.graph.steps[step_id].kind)): step_id
        for step_id, position in right_positions.items()
    }
    changed: list[StepChange] = []
    consumed_left: set[str] = set()
    consumed_right: set[str] = set()
    for left_id, position in left_positions.items():
        left_step = left.graph.steps[left_id]
        right_id = right_by_position.get((position, str(left_step.kind)))
        if right_id is None:
            continue
        right_step = right.graph.steps[right_id]
        consumed_left.add(left_id)
        consumed_right.add(right_id)
        deltas = (
            _fields(left_step, right_step) if left_id != right_id else _drift(left_step, right_step)
        )
        if deltas:
            changed.append(StepChange(left_step, right_step, deltas))
    only_left = [
        left.graph.steps[step_id]
        for step_id in left.graph.order
        if step_id in left_ids - right_ids and step_id not in consumed_left
    ]
    only_right = [
        right.graph.steps[step_id]
        for step_id in right.graph.order
        if step_id in right_ids - left_ids and step_id not in consumed_right
    ]
    return RunDiff(common, only_left, only_right, changed)
