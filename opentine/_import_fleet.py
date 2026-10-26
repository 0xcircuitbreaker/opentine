"""``tine import --fleet``: a Claude Code session as a fleet of runs.

A plain import keeps every subagent inside the session's one run. With
``--fleet`` the session's own events become the **root** run and each subagent
(its ``agent-<id>/`` events) a **child** run forked at the tool step that
spawned it -- so ``tine diff``, ``cost`` and ``replay`` work per subagent. A
nested subagent forks from its parent subagent's run. A subagent whose spawning
step is unknown (no ``agentId`` in a tool result: an orphan) becomes a
standalone child, still linked to the root.

Every member run carries an ``opentine-agent/1`` record with lineage (``parent``
= the spawner's agent ref, ``parent_run``, ``spawn_step``) and the root carries
the manifest ``opentine.fleet`` = ``{format, root, members[...]}``. A forked
child shares its inherited steps with the spawner, so the fleet's cost counts
each step once (:func:`fleet_cost`) and equals the single-run import's cost.

Agent ids come from transcript file names: they are clamped to ref-safe text
(``a-`` + lowercase ``[a-z0-9._-]``, at most 64 chars, else a digest) before naming
``heads/fleet/<root>/<agent>``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from decimal import Decimal
from typing import Any

from opentine import _agent_identity as identity
from opentine._import_write import annotate, import_identity, record
from opentine.trace._span_state import span_key
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TraceEvent

FORMAT = "opentine-fleet/1"
_PREFIX = re.compile(r"agent-([^/]{1,200})/")
_REF_UNSAFE = re.compile(r"[^a-z0-9._-]")


def ref_component(agent: str) -> str:
    text = _REF_UNSAFE.sub("-", agent.lower()).strip(".-")[:62]
    if not text or ".." in text or text.endswith(".lock"):
        text = hashlib.sha256(agent.encode()).hexdigest()[:16]
    return "a-" + text  # never a bare reserved name (con, nul...)


def split(events: list[TraceEvent]) -> tuple[list[TraceEvent], dict[str, list[TraceEvent]]]:
    main: list[TraceEvent] = []
    groups: dict[str, list[TraceEvent]] = {}
    for item in events:
        match = _PREFIX.match(item.span_id or "")
        if match:
            groups.setdefault(match.group(1), []).append(item)
        else:
            main.append(item)
    return main, groups


def _spawner(group: list[TraceEvent]) -> str | None:
    edge = next((item for item in group if item.kind == "subagent"), None)
    return edge.parent_span_id if edge is not None else None


def _owner(span: str | None) -> str:
    match = _PREFIX.match(span or "")
    return match.group(1) if match else ""


def _type_from_spawn(events: list[TraceEvent], spawner: str | None) -> str:
    local = (spawner or "").rsplit("/", 1)[-1]
    if not local.startswith("tool:"):
        return ""
    call = local.split("#", 1)[0].removeprefix("tool:")
    for item in events:
        for tool_call in (item.outputs or {}).get("tool_calls") or []:
            if isinstance(tool_call, dict) and tool_call.get("id") == call:
                args = tool_call.get("input")
                kind = args.get("subagent_type") if isinstance(args, dict) else None
                return identity.normalize_name(kind)[:64] if isinstance(kind, str) else ""
    return ""


def record_fleet(
    repo: Any,
    events: list[TraceEvent],
    ref: str,
    capture: dict | None,
    source_format: str,
    journal: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Record the root and one child per subagent; the fleet manifest."""
    main, groups = split(events)
    if not main:
        raise ValueError("the session has no events of its own to root a fleet")
    recorder = Recorder.start(repo, ref=ref, capture=False)
    recorder.import_events(main, trusted_billing=True)
    root = recorder.finalize()
    root_identity = import_identity(source_format, main)
    runs: dict[str, tuple[str, dict, dict[str, Any] | None]] = {
        "": (root, dict(recorder.span_map), root_identity)
    }
    tag = hashlib.sha256(root.encode()).hexdigest()[:12]
    members: list[dict[str, Any]] = []
    used: set[str] = set()
    pending = list(groups)
    while pending:
        ready = [a for a in pending if _owner(_spawner(groups[a])) in runs or not _waits(a, groups)]
        if not ready:  # a spawn cycle: break it with standalone children
            ready = pending[:1]
        for agent in ready:
            pending.remove(agent)
            members.append(_child(repo, agent, groups[agent], runs, events, tag, used, journal))
            runs[agent] = members[-1].pop("_state")
    manifest = {"format": FORMAT, "root": root, "members": members}
    metadata = {"capture": capture, "agent_identity": root_identity, "opentine.fleet": manifest}
    annotate(repo, root, metadata)
    return manifest


def _waits(agent: str, groups: dict[str, list[TraceEvent]]) -> bool:
    """True while the agent's spawner is another subagent not yet recorded."""
    owner = _owner(_spawner(groups[agent]))
    return bool(owner) and owner in groups and owner != agent


def _child(repo, agent, group, runs, events, tag, used, journal) -> dict[str, Any]:
    spawner = _spawner(group)
    owner_run, span_map, owner_identity = runs.get(_owner(spawner), runs[""])
    trace_id = group[0].trace_id
    spawn_event = span_map.get(span_key(trace_id, spawner)) if spawner else None
    name = ref_component(agent)
    while name in used:
        name = f"{name[:56]}-{len(used)}"
    used.add(name)
    child_ref = f"heads/fleet/{tag}/{name}"
    if spawn_event:
        fork_id = repo.fork(owner_run, spawn_event, ref=child_ref)
        recorder = Recorder.resume(repo, fork_id, ref=child_ref)
    else:  # orphan: no spawning step to fork from
        group = [replace(group[0], parent_span_id=None), *group[1:]]
        recorder = Recorder.start(repo, ref=child_ref, capture=False)
    recorder.import_events(group, trusted_billing=True)
    run_id = recorder.finalize()
    agent_type = _type_from_spawn(events, spawner) or (journal or {}).get(agent, "")
    parent_ref = identity.agent_ref(owner_identity) if owner_identity else ""
    record_ = import_identity(
        "",
        group,
        harness=f"claude-code/{agent_type}" if agent_type else "claude-code",
        parent=parent_ref,
        parent_run=owner_run,
        spawn_step=spawn_event or "",
    )
    member = {
        "agent_id": agent,
        "agent_type": agent_type,
        "run_id": run_id,
        "ref": child_ref,
        "parent_run": owner_run,
        "spawn_step": spawn_event or "",
    }
    annotate(
        repo,
        run_id,
        {
            "capture": {"method": "transcript-import", "source_format": "claude-code-transcript",
                        "agent_writable": True},
            "agent_identity": record_,
            "opentine.fleet": {"format": FORMAT, "member": agent, "root": runs[""][0]},
        },
    )  # fmt: skip
    return {**member, "_state": (run_id, dict(recorder.span_map), record_)}


def fleet_cost(repo: Any, manifest: dict[str, Any]) -> Decimal:
    """The fleet's cost, each step counted once across its member runs."""
    from opentine._graph_run import _step_cost_decimal
    from opentine.billing._context import billing_context

    seen: set[str] = set()
    total = Decimal(0)
    run_ids = [manifest["root"], *(m["run_id"] for m in manifest.get("members") or [])]
    with billing_context():
        for run_id in run_ids:
            for step in repo.load_run(run_id).steps:
                if step.id not in seen:
                    seen.add(step.id)
                    total += _step_cost_decimal(step)
    return total


__all__ = ["FORMAT", "fleet_cost", "record", "record_fleet", "ref_component", "split"]
