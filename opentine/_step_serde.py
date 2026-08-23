"""Legacy .tine v2 step serialization, split out of the run-level serde.

Both halves live here so a field added to :class:`~opentine._graph_types.Step`
cannot be written without a reader for it — the writer/reader asymmetry the
parity gate exists to catch. Additive fields are emitted only when non-empty, so
an artifact written before the field existed re-serializes byte for byte.
"""

from __future__ import annotations

from typing import Any

from opentine._graph_run import _usage
from opentine._graph_types import Step, StepKind
from opentine._v3_guards import text_field


def step_to_dict(step: Step) -> dict[str, Any]:
    data = {
        "cost": step.cost,
        "duration": step.duration,
        "error": step.error,
        "id": step.id,
        "inputs": step.inputs,
        "kind": step.kind.value,
        "model_info": step.model_info,
        "outputs": step.outputs,
        "parent_ids": list(step.parent_ids),
        "timestamp": step.timestamp,
        "tool_info": step.tool_info,
        # Additive and absent when empty: a v3 run exported here used to lose
        # every causal edge, silently shrinking a later fork's retained slice,
        # while a run that never had one still writes the bytes it always did.
        **({"causal_ids": list(step.causal_ids)} if step.causal_ids else {}),
        # Same contract for the step's provider: recorded when the run knows it,
        # absent otherwise, so every pre-0.8.0 artifact round-trips unchanged.
        **({"provider": step.provider} if step.provider else {}),
    }
    if step.usage:
        data["usage"] = dict(step.usage)
    if step.billing:
        data["billing"] = dict(step.billing)
    return data


def step_from_dict(data: dict[str, Any]) -> Step:
    parents = data.get("parent_ids")
    if parents is None:
        parents = [parent] if (parent := data.get("parent_id")) else []
    return Step(
        id=data["id"],
        parent_ids=list(parents),
        kind=StepKind(data["kind"]),
        inputs=dict(data.get("inputs") or {}),
        outputs=dict(data.get("outputs") or {}),
        model_info=data.get("model_info", ""),
        tool_info=dict(data.get("tool_info") or {}),
        error=dict(data.get("error") or {}),
        timestamp=float(data.get("timestamp") or 0),
        duration=0 if data.get("duration") is None else data["duration"],
        cost=0 if data.get("cost") is None else data["cost"],
        usage=_usage(data.get("usage")),
        billing=dict(data.get("billing") or {}),
        causal_ids=list(data.get("causal_ids") or []),
        # Same rule the v3 loader applies: nothing validates this field, so a
        # foreign artifact's non-string provider falls back rather than crashing
        # the load or reaching the writer as a shape it cannot re-emit.
        provider=text_field(data.get("provider")),
    )
