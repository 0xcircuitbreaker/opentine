"""Fail-closed structural checks for portable v1/v2 run graphs."""

from __future__ import annotations

import math
from typing import Any


def validate_run_record(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("artifact root must be an object")
    required = {
        "cache",
        "created_at",
        "format_version",
        "graph",
        "manifest",
        "metadata",
        "policies",
        "refs",
        "run_id",
        "status",
        "transcript",
    }
    if missing := sorted(required - data.keys()):
        raise ValueError(f"artifact is missing required field(s): {', '.join(missing)}")
    run_id = data.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("artifact run_id must be a non-empty string")
    for field in ("refs", "manifest", "policies", "cache", "metadata"):
        if not isinstance(data.get(field, {}), dict):
            raise ValueError(f"artifact {field} must be an object")
    if not isinstance(data.get("transcript", []), list):
        raise ValueError("artifact transcript must be a list")
    refs = data.get("refs", {})
    if any(
        not isinstance(name, str) or not isinstance(target, str) for name, target in refs.items()
    ):
        raise ValueError("artifact refs must map string names to string step IDs")
    graph = data.get("graph", {})
    steps = graph.get("steps", {}) if isinstance(graph, dict) else {}
    if any(target and target not in steps for target in refs.values()):
        raise ValueError("artifact refs must point to stored graph steps")
    metadata = data.get("metadata", {})
    for field in ("model_info", "system_prompt", "user_prompt"):
        if field in metadata and not isinstance(metadata[field], str):
            raise ValueError(f"artifact metadata.{field} must be a string")
    tags = metadata.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError("artifact metadata.tags must be a list of strings")
    model = data.get("manifest", {}).get("model")
    if model is not None and (
        not isinstance(model, dict) or ("name" in model and not isinstance(model["name"], str))
    ):
        raise ValueError("artifact manifest.model must be an object with a string name")
    created_at = data.get("created_at", 0)
    try:
        finite_created_at = math.isfinite(float(created_at))
    except (OverflowError, TypeError, ValueError):
        finite_created_at = False
    if (
        isinstance(created_at, bool)
        or type(created_at) not in {int, float}
        or not finite_created_at
    ):
        raise ValueError("artifact created_at must be a finite number")
    if "draft" in data and not isinstance(data["draft"], bool):
        raise ValueError("artifact draft must be a boolean")
    return data


def ordered_step_records(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        raise ValueError("artifact graph must be an object")
    steps = data.get("steps", {})
    if not isinstance(steps, dict) or any(not isinstance(key, str) for key in steps):
        raise ValueError("artifact graph.steps must be an object with string keys")
    order = data.get("order")
    if "order" not in data:
        order = list(steps)
    if not isinstance(order, list) or any(not isinstance(step_id, str) for step_id in order):
        raise ValueError("artifact graph.order must be a list of step IDs")
    if len(order) != len(set(order)):
        raise ValueError("artifact graph.order contains duplicate step IDs")
    if len(order) != len(steps) or set(order) != set(steps):
        raise ValueError("artifact graph.order must contain every stored step exactly once")
    records: list[dict[str, Any]] = []
    for step_id in order:
        record = steps[step_id]
        if not isinstance(record, dict):
            raise ValueError(f"artifact step {step_id!r} must be an object")
        if record.get("id") != step_id:
            raise ValueError(f"artifact step key and embedded ID differ: {step_id!r}")
        _validate_step_record(record, step_id)
        records.append(record)
    return records


def _validate_step_record(record: dict[str, Any], step_id: str) -> None:
    required = {
        "cost",
        "duration",
        "error",
        "id",
        "inputs",
        "kind",
        "model_info",
        "outputs",
        "timestamp",
        "tool_info",
    }
    if missing := sorted(required - record.keys()):
        raise ValueError(f"artifact step {step_id!r} is missing: {', '.join(missing)}")
    parents = record.get("parent_ids")
    if parents is None:
        parent = record.get("parent_id")
        if parent is not None and not isinstance(parent, str):
            raise ValueError(f"artifact step {step_id!r} parent_id must be a string")
    elif not isinstance(parents, list) or any(not isinstance(item, str) for item in parents):
        raise ValueError(f"artifact step {step_id!r} parent_ids must be a list of strings")
    for field in ("inputs", "outputs", "tool_info", "error", "usage", "billing"):
        value = record.get(field)
        if value is not None and not isinstance(value, dict):
            raise ValueError(f"artifact step {step_id!r} {field} must be an object")
    timestamp = record.get("timestamp", 0)
    try:
        finite_timestamp = math.isfinite(float(timestamp))
    except (OverflowError, TypeError, ValueError):
        finite_timestamp = False
    if isinstance(timestamp, bool) or type(timestamp) not in {int, float} or not finite_timestamp:
        raise ValueError(f"artifact step {step_id!r} timestamp must be a finite number")
