"""Export a run as one ATIF trajectory (``tine export --format atif``).

The inverse of :mod:`opentine._atif` for what ATIF can carry: ``model``,
``think``, ``done`` and ``error`` steps become ``agent`` steps, ``human`` steps
``user`` steps, and each ``tool`` step an ``agent`` step holding one tool call
and its observation. Usage is written the way ATIF defines it --
``prompt_tokens`` *includes* cache reads and writes, ``completion_tokens``
includes reasoning -- with the exclusive buckets restored in ``metrics.extra``,
so an export imports back to the same usage. ``cost_usd`` is the run's own
recorded cost; an importer prices from its catalog regardless. Subagent steps
stay in this one trajectory (their parent links are opentine's, not ATIF's).

The caller redacts the run first; this module only reshapes it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from opentine._version import __version__

SCHEMA_VERSION = "ATIF-v1.8"


def _iso(seconds: float) -> str | None:
    if not seconds or seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _text(payload: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str):
            return value
    return ""


def _metrics(step: Any) -> dict[str, Any]:
    usage = step.usage or {}

    def amount(name: str) -> int:
        value = usage.get(name)
        return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0

    cache_read = amount("cache_read")
    cache_write = amount("cache_write_5m") + amount("cache_write_1h")
    reasoning = amount("reasoning")
    metrics: dict[str, Any] = {}
    if usage:
        metrics = {
            "prompt_tokens": amount("input") + cache_read + cache_write,
            "completion_tokens": amount("output") + reasoning,
            "cached_tokens": cache_read,
            "extra": {
                "reasoning_tokens": reasoning,
                "cache_creation_input_tokens": cache_write,
            },
        }
    if step.cost:
        metrics["cost_usd"] = step.cost
    return metrics


def _step(step: Any, number: int) -> dict[str, Any]:
    kind = step.v3_kind or getattr(step.kind, "value", str(step.kind))
    inputs, outputs = step.inputs or {}, step.outputs or {}
    item: dict[str, Any] = {"step_id": number}
    if when := _iso(step.timestamp):
        item["timestamp"] = when
    if kind == "human":
        item.update(source="user", message=_text(inputs, "text", "prompt", "content"))
        return item
    item["source"] = "agent"
    if step.model_info:
        item["model_name"] = step.model_info
    if kind == "tool":
        name = str(inputs.get("name") or step.tool_info.get("name") or "tool")
        call_id = f"call-{step.id[:16]}"
        arguments = inputs.get("arguments")
        item["message"] = ""
        item["tool_calls"] = [
            {
                "tool_call_id": call_id,
                "function_name": name,
                "arguments": arguments if isinstance(arguments, dict) else {"input": arguments},
            }
        ]
        result = outputs.get("result", outputs.get("output", outputs))
        item["observation"] = {
            "results": [
                {
                    "source_call_id": call_id,
                    "content": result if isinstance(result, str) else str(result),
                }
            ]
        }
    else:
        item["message"] = _text(outputs, "text", "content", "result") or _text(
            inputs, "text", "error"
        )
        if isinstance(outputs.get("reasoning"), str):
            item["reasoning_content"] = outputs["reasoning"]
    if metrics := _metrics(step):
        item["metrics"] = metrics
    extra = {"opentine.kind": kind, "opentine.step_id": step.id}
    if step.provider:
        extra["provider"] = step.provider
    item["extra"] = extra
    return item


def to_atif(run: Any) -> dict[str, Any]:
    """One ATIF v1.8 trajectory document for *run*."""
    steps = [_step(step, number) for number, step in enumerate(run.steps, start=1)]
    totals = {"prompt": 0, "completion": 0, "cached": 0}
    cost = 0.0
    for item in steps:
        metrics = item.get("metrics") or {}
        totals["prompt"] += metrics.get("prompt_tokens", 0)
        totals["completion"] += metrics.get("completion_tokens", 0)
        totals["cached"] += metrics.get("cached_tokens", 0)
        cost += float(metrics.get("cost_usd", 0) or 0)
    metadata = run.metadata if isinstance(getattr(run, "metadata", None), dict) else {}
    agent = {
        "name": str(metadata.get("harness") or "opentine"),
        "version": __version__,
    }
    if run.model_info:
        agent["model_name"] = run.model_info
    return {
        "schema_version": SCHEMA_VERSION,
        "session_id": run.id,
        "trajectory_id": run.id,
        "agent": agent,
        "steps": steps,
        "final_metrics": {
            "total_prompt_tokens": totals["prompt"],
            "total_completion_tokens": totals["completion"],
            "total_cached_tokens": totals["cached"],
            "total_cost_usd": round(cost, 10),
            "total_steps": len(steps),
        },
        "extra": {"opentine.run_id": run.id, "opentine.status": str(run.status)},
    }


__all__ = ["SCHEMA_VERSION", "to_atif"]
