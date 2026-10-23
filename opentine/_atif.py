"""Import Harbor's Agent Trajectory Interchange Format (ATIF) as trace events.

ATIF (https://github.com/harbor-framework/harbor/blob/main/rfcs/0001-trajectory-format.md,
v1.0 through v1.8) is one JSON document per trajectory: a root naming the agent
and its default model, a list of ``steps`` (``system``/``user``/``agent``), each
agent step's ``tool_calls`` answered by ``observation.results`` correlated through
``source_call_id``, and -- since v1.7 -- subagent trajectories embedded under
``subagent_trajectories`` and referenced from a result's
``subagent_trajectory_ref``.

Mapping, and what is deliberately not trusted:

* an agent step becomes a ``model`` event; its usage is ``metrics`` read the way
  ATIF defines it -- ``prompt_tokens`` *includes* ``cached_tokens`` and
  ``completion_tokens`` includes reasoning -- into exclusive buckets;
* ``cost_usd`` is the file's claim, kept only as ``atif.cost_usd``: an import is
  priced from the catalog, never from what the source says it cost;
* each tool call becomes a ``tool`` event carrying its observation;
* an embedded subagent becomes a typed ``subagent`` event under the tool call
  that delegated it, and its own steps hang under that edge. A subagent named
  only by ``trajectory_path`` (a file, URL or database reference) is never
  followed: a document must not make the importer open other files;
* ``is_copied_context`` steps (context carried across a summarization boundary)
  are kept as context without usage, so they are not billed twice.

Bounded like every importer: the document's bytes and structure are checked
before it is parsed, at most :data:`MAX_TRAJECTORIES` trajectories nested at
most :data:`MAX_DEPTH` deep, and the transcript event cap overall.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any

from opentine._atif_parse import (
    ATIF_FORMAT,
    MAX_DEPTH,
    MAX_TOOL_CALLS,
    MAX_TRAJECTORIES,
    is_atif,
    load,
    model_provider,
)
from opentine.trace._import_helpers import note_import_warning
from opentine.trace._transcript_common import (
    MAX_EVENTS,
    SHAPE_ERRORS,
    Chain,
    bounded_id,
    label,
    session_trace_id,
    text_of,
)
from opentine.trace._transcript_usage import count, inclusive_usage
from opentine.trace.schema import TraceEvent


class _Import:
    def __init__(self, root: dict[str, Any]) -> None:
        self.embedded: dict[str, dict[str, Any]] = {}
        self._collect(root, 0)
        session = root.get("session_id") or root.get("trajectory_id") or "atif"
        self.trace_id = session_trace_id(session)
        self.events: list[TraceEvent] = []
        self.imported: set[str] = set()
        self.trajectories = 0
        self.skipped = 0
        self.unfollowed = 0
        self._queues: list[list[tuple[dict[str, Any], str, str]]] = []

    def _collect(self, trajectory: dict[str, Any], depth: int) -> None:
        """Index every embedded subagent trajectory by ``trajectory_id``, bounded."""
        stack = [(trajectory, depth)]
        while stack:
            current, level = stack.pop()
            subs = current.get("subagent_trajectories")
            if not isinstance(subs, list) or level >= MAX_DEPTH:
                continue
            for sub in subs:
                if len(self.embedded) >= MAX_TRAJECTORIES:
                    return
                if isinstance(sub, dict) and isinstance(sub.get("trajectory_id"), str):
                    self.embedded.setdefault(sub["trajectory_id"], sub)
                    stack.append((sub, level + 1))

    def trajectory(self, data: dict[str, Any], prefix: str, parent: str | None, depth: int) -> None:
        self.trajectories += 1
        if self.trajectories > MAX_TRAJECTORIES or depth > MAX_DEPTH:
            self.unfollowed += 1
            return
        agent = data.get("agent") if isinstance(data.get("agent"), dict) else {}
        chain = Chain(self.trace_id, prefix=prefix, parent=parent)  # one trace, all agents
        self._queues.append([])
        steps = data.get("steps") if isinstance(data.get("steps"), list) else []
        for step in steps:
            if not isinstance(step, dict):
                self.skipped += 1
                continue
            try:
                self._step(step, agent, chain, prefix, depth)
            except SHAPE_ERRORS:
                self.skipped += 1
            if len(self.events) + len(chain.events) > MAX_EVENTS:
                raise ValueError("trace import exceeds maximum event count")
        self.events.extend(chain.events)
        # Subagents after their parent's events, so every parent span precedes its children.
        for sub, sub_prefix, edge_span in self._queues.pop():
            self.trajectory(sub, sub_prefix, edge_span, depth + 1)

    def _step(self, step: dict[str, Any], agent: dict, chain: Chain, prefix: str, depth: int):
        source = step.get("source")
        when = step.get("timestamp")
        span = f"step-{step.get('step_id', len(chain.events) + 1)}"
        message = text_of(step.get("message"))
        attributes = {"source": ATIF_FORMAT}
        if step.get("is_copied_context") is True:
            attributes["atif.is_copied_context"] = True
        if source in ("user", "system"):
            chain.add("human", when, span, actor=source, inputs={"role": source, "text": message},
                      attributes=attributes)  # fmt: skip
            return
        if source != "agent":
            self.skipped += 1
            return
        raw_model = str(step.get("model_name") or agent.get("model_name") or "")[:256]
        model, provider = model_provider(raw_model, step.get("extra"), agent.get("extra"))
        metrics = step.get("metrics") if isinstance(step.get("metrics"), dict) else {}
        extra = metrics.get("extra") if isinstance(metrics.get("extra"), dict) else {}
        usage = {}
        if not attributes.get("atif.is_copied_context"):  # already billed where it ran
            usage = inclusive_usage(metrics.get("prompt_tokens"), metrics.get("cached_tokens"),
                                    metrics.get("completion_tokens"), extra.get("reasoning_tokens"),
                                    extra.get("cache_creation_input_tokens"))  # fmt: skip
        if isinstance(metrics.get("cost_usd"), (int, float)) and not isinstance(
            metrics.get("cost_usd"), bool
        ):
            attributes["atif.cost_usd"] = metrics["cost_usd"]
        if count(step.get("llm_call_count")):
            attributes["atif.llm_call_count"] = count(step.get("llm_call_count"))
        outputs: dict[str, Any] = {"text": message}
        if isinstance(step.get("reasoning_content"), str):
            outputs["reasoning"] = step["reasoning_content"]
        chain.add("model", when, span, actor=label(agent.get("name")), model=model,
                  provider=provider, outputs=outputs, usage=usage,
                  attributes=attributes)  # fmt: skip
        self._tools(step, chain, prefix, depth, when, span)

    def _tools(self, step: dict, chain: Chain, prefix: str, depth: int, when: Any, span: str):
        observation = step.get("observation") if isinstance(step.get("observation"), dict) else {}
        results = observation.get("results") if isinstance(observation.get("results"), list) else []
        by_call = {r.get("source_call_id"): r for r in results if isinstance(r, dict)}
        calls = step.get("tool_calls") if isinstance(step.get("tool_calls"), list) else []
        answered: set[Any] = set()
        for call in calls[:MAX_TOOL_CALLS]:
            if not isinstance(call, dict):
                continue
            call_id = call.get("tool_call_id")
            result = by_call.get(call_id) if call_id is not None else None
            answered.add(call_id)
            name = label(call.get("function_name"))
            chain.add("tool", when, f"{span}/call-{bounded_id(call_id, 'call')}", actor=name,
                      inputs={"name": name, "arguments": call.get("arguments"),
                              "tool_call_id": bounded_id(call_id, "call")},
                      outputs={"result": text_of((result or {}).get("content"))},
                      attributes={"source": ATIF_FORMAT})  # fmt: skip
            self._subagents(result, chain, prefix, depth)
        for result in results[:MAX_TOOL_CALLS]:
            if not isinstance(result, dict) or result.get("source_call_id") in answered:
                continue
            chain.add("tool", when, f"{span}/observation", actor="observation",
                      outputs={"result": text_of(result.get("content"))},
                      attributes={"source": ATIF_FORMAT})  # fmt: skip
            self._subagents(result, chain, prefix, depth)

    def _subagents(self, result: Any, chain: Chain, prefix: str, depth: int) -> None:
        refs = result.get("subagent_trajectory_ref") if isinstance(result, dict) else None
        if not isinstance(refs, list):
            return
        for ref in refs[:MAX_TOOL_CALLS]:
            if not isinstance(ref, dict):
                continue
            target = ref.get("trajectory_id")
            sub = self.embedded.get(target) if isinstance(target, str) else None
            if sub is None or target in self.imported:
                self.unfollowed += sub is None  # file-ref only: never opened
                continue
            self.imported.add(target)
            key = bounded_id(target, "trajectory")
            sub_agent = sub.get("agent") if isinstance(sub.get("agent"), dict) else {}
            edge = f"sub-{key}"
            when = chain.events[-1].timestamp if chain.events else None
            session = ref.get("session_id")
            chain.add(
                "subagent",
                when,
                edge,
                actor=label(sub_agent.get("name")),
                inputs={
                    "trajectory_id": key,
                    "session_id": bounded_id(session, "session") if session else "",
                },
                attributes={"source": ATIF_FORMAT},
            )
            self._queues[-1].append((sub, f"{prefix}{edge}/", chain.events[-1].span_id))


def atif_events(source: str | Path | Iterable[Any]) -> list[TraceEvent]:
    """Events for an ATIF trajectory file (or its lines), subagents included."""
    document = load(source)
    if not is_atif(document):
        raise ValueError("not an ATIF trajectory (schema_version ATIF-v1.x and steps required)")
    state = _Import(document)
    state.trajectory(document, "", None, 0)
    events = state.events
    notes = []
    if state.skipped:
        notes.append(f"skipped {state.skipped} ATIF step(s) with unexpected shape")
    if state.unfollowed:
        notes.append(f"{state.unfollowed} subagent trajectory reference(s) not followed")
    if events and notes:
        attributes = dict(events[0].attributes or {})
        for note in notes:
            note_import_warning(attributes, note)
        events[0] = replace(events[0], attributes=attributes)
    return events


__all__ = ["ATIF_FORMAT", "atif_events", "is_atif", "model_provider"]
