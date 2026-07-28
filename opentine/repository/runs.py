"""Conversion between compatibility ``Run`` objects and immutable v3 objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from opentine._artifact_io import read_artifact_bytes as read_artifact_bytes
from opentine._canon import _redact
from opentine._jsonsafe import json_safe
from opentine.repository._annotations import load_run_annotation, write_run_annotation
from opentine.repository._migration_preflight import preflight_run
from opentine.repository._run_blobs import (
    blob_json,
    json_blob,
    put_run_manifest,
    put_transcript,
    run_origin,
    transcript_blob,
)
from opentine.repository._run_graph import compatibility_float

if TYPE_CHECKING:
    from opentine.graph import Run
    from opentine.repository.store import Repo


@dataclass(frozen=True)
class RunObjectResult:
    run_id: str
    event_map: dict[str, str]
    annotation_id: str | None = None


def _put_run(
    repo: Repo,
    run: Run,
    *,
    ref: str | None = None,
    legacy_blob: str | None = None,
    legacy_verification: dict[str, Any] | None = None,
) -> RunObjectResult:
    base = run_origin(repo, run)
    provenance = getattr(run, "_v3_source_payload", None)
    if provenance is None:
        provenance = getattr(run, "_v3_payload", None)
    reusable_events = (
        set(provenance.get("events") or ())
        if legacy_blob is None and isinstance(provenance, dict)
        else set()
    )
    event_map: dict[str, str] = {}
    events: list[str] = []
    for step in run.steps:
        if step.id in reusable_events:
            if not repo.has(step.id):
                raise ValueError("cannot reconstruct a foreign v3 event through compatibility Run")
            prior = repo.get(step.id).payload()
            event_id = repo.put("event", prior)
            event_map[step.id] = event_id
            events.append(event_id)
            continue
        input_blob = json_blob(repo, step.inputs)
        output_blob = json_blob(repo, step.outputs)
        raw_kind = step.v3_kind or step.kind.value
        tool = step.tool_info
        causal = getattr(run, "_v3_causal_ids", {}).get(step.id, [])
        payload = {
            "billing": _redact(step.billing),
            "causal_ids": [event_map[item] for item in causal],
            "cost": step.cost,
            "duration": step.duration,
            "error": _redact(step.error),
            "input_blob": input_blob,
            "kind": raw_kind,
            "legacy_step_id": step.id,
            "model": step.model_info,
            "output_blob": output_blob,
            "parent_ids": [event_map[parent] for parent in step.parent_ids],
            "time_unix": step.timestamp,
            "tool": _redact(tool),
            "usage": _redact(step.usage),
        }
        event_id = repo.put("event", json_safe(payload))
        event_map[step.id] = event_id
        events.append(event_id)

    roots = [event_map[step.id] for step in run.root_steps()]
    parents = {parent for step in run.steps for parent in step.parent_ids}
    tips = [event_map[step.id] for step in run.steps if step.id not in parents]
    legacy_refs = {
        str(name): event_map[target]
        for name, target in run.refs.items()
        if target and target in event_map
    }
    manifests = dict(base.get("manifests") or {})
    manifests.update(
        {
            "cache": json_blob(repo, run.cache),
            "policy": json_blob(repo, run.policies),
            "run": put_run_manifest(repo, run.manifest, event_map),
            "transcript": put_transcript(repo, run.transcript, event_map),
        }
    )
    migration_map_blob = json_blob(repo, event_map) if legacy_blob else None
    payload: dict[str, Any] = {
        **base,
        "created_at": run.created_at,
        "events": events,
        "legacy_refs": legacy_refs,
        "manifests": manifests,
        "model": run.model_info,
        "roots": roots,
        "source_run_id": run.id,
        "status": run.status.value,
        "system_blob": repo.put("blob", run.system_prompt.encode()),
        "prompt_blob": repo.put("blob", run.user_prompt.encode()),
        "tips": tips,
    }
    if legacy_blob:
        payload.update(
            {
                "legacy_blob": legacy_blob,
                "legacy_format": 2,
                "legacy_verification": legacy_verification or {},
                "migration_map_blob": migration_map_blob,
                "signature_scope": "legacy_blob_only",
            }
        )
    run_id = repo.put("run", json_safe(payload))
    annotation_id = write_run_annotation(repo, run_id, run.metadata, run.tags)
    if ref:
        old = repo.read_ref(ref)
        repo.update_ref(ref, run_id, expected_old=old)
    return RunObjectResult(run_id, event_map, annotation_id)


def put_run(
    repo: Repo,
    run: Run,
    *,
    ref: str | None = None,
    legacy_blob: str | None = None,
    legacy_verification: dict[str, Any] | None = None,
) -> RunObjectResult:
    preflight_run(
        repo,
        run,
        ref=ref,
        legacy_blob=legacy_blob,
        legacy_verification=legacy_verification,
    )
    return _put_run(
        repo,
        run,
        ref=ref,
        legacy_blob=legacy_blob,
        legacy_verification=legacy_verification,
    )


def load_run(repo: Repo, oid_or_ref: str) -> Run:
    from opentine.graph import Graph, Run, RunStatus, Step, StepKind

    oid = repo.read_ref(oid_or_ref) if not oid_or_ref.startswith("run:") else oid_or_ref
    if not oid:
        raise KeyError(oid_or_ref)
    payload = repo.get(oid).payload()
    if not isinstance(payload, dict):
        raise ValueError("run object payload is not a mapping")
    graph = Graph()
    causal_ids: dict[str, list[str]] = {}
    for event_id in payload.get("events") or []:
        event = repo.get(event_id).payload()
        causal_ids[event_id] = list(event.get("causal_ids") or [])
        raw_kind = str(event.get("kind", "model"))
        legacy_kind = (
            StepKind(raw_kind) if raw_kind in StepKind._value2member_map_ else StepKind.model
        )
        graph.add(
            Step(
                id=event_id,
                parent_ids=list(event.get("parent_ids") or []),
                kind=legacy_kind,
                inputs=blob_json(repo, event["input_blob"]) if event.get("input_blob") else {},
                outputs=blob_json(repo, event["output_blob"]) if event.get("output_blob") else {},
                model_info=event.get("model", ""),
                tool_info=dict(event.get("tool") or {}),
                error=dict(event.get("error") or {}),
                timestamp=float(event.get("time_unix") or 0),
                duration=compatibility_float(event.get("duration") or 0, "event duration"),
                cost=compatibility_float(event.get("cost") or 0, "event cost"),
                usage=dict(event.get("usage") or {}),
                billing=dict(event.get("billing") or {}),
                v3_kind=raw_kind,
            )
        )
    manifest_id = (payload.get("manifests") or {}).get("run")
    policy_id = (payload.get("manifests") or {}).get("policy")
    cache_id = (payload.get("manifests") or {}).get("cache")
    transcript_id = (payload.get("manifests") or {}).get("transcript")
    refs = dict(payload.get("legacy_refs") or {})
    refs.setdefault("main", (payload.get("tips") or [""])[-1] if payload.get("tips") else "")
    run = Run(
        id=payload.get("source_run_id") or oid,
        status=RunStatus(payload.get("status", "running")),
        graph=graph,
        refs=refs,
        transcript=transcript_blob(repo, transcript_id),
        manifest=blob_json(repo, manifest_id) if manifest_id else {},
        policies=blob_json(repo, policy_id) if policy_id else {},
        cache=blob_json(repo, cache_id) if cache_id else {},
        created_at=float(payload.get("created_at") or 0),
    )
    system_blob = payload.get("system_blob")
    prompt_blob = payload.get("prompt_blob")
    run.system_prompt = repo.get(system_blob).body.decode(errors="replace") if system_blob else ""
    run.user_prompt = repo.get(prompt_blob).body.decode(errors="replace") if prompt_blob else ""
    run.model_info = payload.get("model") or run.manifest.get("model", {}).get("name", "")
    run.metadata, tags = load_run_annotation(repo, oid)
    for tag in tags:
        run.add_tag(tag)
    run._v3_causal_ids = causal_ids
    run._v3_payload = dict(payload)
    run._v3_run_id = oid
    return run
