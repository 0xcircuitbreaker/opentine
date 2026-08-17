"""Conversion between compatibility ``Run`` objects and immutable v3 objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from opentine._artifact_io import read_artifact_bytes as read_artifact_bytes
from opentine._canon import _redact
from opentine._jsonsafe import json_safe
from opentine._unicode_text import assert_unicode_text
from opentine._v3_guards import as_mapping, text_field
from opentine.repository._annotations import load_run_annotation, write_run_annotation
from opentine.repository._migration_preflight import preflight_run
from opentine.repository._run_blobs import (
    apply_legacy_migration,
    blob_json,
    json_blob,
    put_run_manifest,
    put_transcript,
    run_origin,
    transcript_blob,
)
from opentine.repository._run_graph import _meter, compatibility_float
from opentine.repository._shallow_read import require_deep

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
    # Raw blobs: the only two strings guarded_redaction never sees, and the meter
    # below is load_run's own, because a value the reader refuses must not be
    # writable -- put_run stored runs every later command then died opening.
    prompts = {"system_prompt": run.system_prompt, "user_prompt": run.user_prompt}
    assert_unicode_text(prompts, where="run prompt")
    _meter(run.created_at or 0, "run created_at", nonnegative=False)
    base = run_origin(repo, run)
    provenance = getattr(run, "_v3_source_payload", None)
    if provenance is None:
        provenance = getattr(run, "_v3_payload", None)
    prior = provenance.get("events") if isinstance(provenance, dict) else None
    if legacy_blob is not None or not isinstance(prior, list):
        prior = ()  # absent, malformed, or a legacy migration: nothing is reusable
    reusable_events = {item for item in prior if isinstance(item, str)}
    causal_map = as_mapping(getattr(run, "_v3_causal_ids", {}))
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
        # The step's own edges are the fallback: a repository run exported to
        # .tine and reloaded carries them there, with no _v3_causal_ids map.
        causal = causal_map.get(step.id) or step.causal_ids
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
            "tool": _redact(step.tool_info),
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
    manifests["cache"] = json_blob(repo, run.cache)
    manifests["policy"] = json_blob(repo, run.policies)
    manifests["run"] = put_run_manifest(repo, run.manifest, event_map)
    manifests["transcript"] = put_transcript(repo, run.transcript, event_map)
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
    apply_legacy_migration(payload, legacy_blob, legacy_verification, migration_map_blob)
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
    # Spelled once: the preflight's job is to reject what the writer below would
    # then attempt, which it can only do if it is handed the identical arguments.
    conversion: dict[str, Any] = {
        "ref": ref,
        "legacy_blob": legacy_blob,
        "legacy_verification": legacy_verification,
    }
    preflight_run(repo, run, **conversion)
    return _put_run(repo, run, **conversion)


def _blob(repo: Repo, cache: dict[str, dict[str, Any]], oid: Any) -> dict[str, Any]:
    """Decode a content blob once per load, not once per event that references it.

    Events routinely share a blob — the same prompt or tool output referenced as
    both input and output across a run. Decoding per reference made an 800 KiB
    repository take minutes and read hundreds of MiB, with no bound that would
    ever stop it. Content addressing makes the result identical, so it is cached;
    a copy is returned because Step mutates what it is given.
    """
    if not isinstance(oid, str) or not oid:
        return {}
    if oid not in cache:
        cache[oid] = blob_json(repo, oid)
    return dict(cache[oid])


def load_run(repo: Repo, oid_or_ref: str) -> Run:
    from opentine.graph import Graph, Run, RunStatus, Step, StepKind

    oid = repo.read_ref(oid_or_ref) if not oid_or_ref.startswith("run:") else oid_or_ref
    if not oid:
        raise KeyError(oid_or_ref)
    payload = repo.get(oid).payload()
    if not isinstance(payload, dict):
        raise ValueError("run object payload is not a mapping")
    require_deep(repo, payload.get("events") or [], f"loading run {oid}")
    graph = Graph()
    blobs: dict[str, dict[str, Any]] = {}
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
                inputs=_blob(repo, blobs, event.get("input_blob")),
                outputs=_blob(repo, blobs, event.get("output_blob")),
                model_info=event.get("model", ""),
                tool_info=as_mapping(event.get("tool")),
                error=as_mapping(event.get("error")),
                timestamp=float(event.get("time_unix") or 0),
                duration=compatibility_float(event.get("duration") or 0, "event duration"),
                cost=compatibility_float(event.get("cost") or 0, "event cost"),
                usage=as_mapping(event.get("usage")),
                billing=as_mapping(event.get("billing")),
                causal_ids=list(causal_ids[event_id]),
                v3_kind=raw_kind,
            )
        )
    manifests = as_mapping(payload.get("manifests"))
    manifest_id, policy_id = manifests.get("run"), manifests.get("policy")
    cache_id, transcript_id = manifests.get("cache"), manifests.get("transcript")
    # Metered like the event timestamps beside it (a clock reading may be negative,
    # unlike a cost). Bare float() raised ValueError/TypeError on a shape nothing
    # validates on a run, and read "1e999999999" back as infinity.
    _meter(payload.get("created_at") or 0, "run created_at", nonnegative=False)
    refs = dict(payload.get("legacy_refs") or {})
    refs.setdefault("main", (payload.get("tips") or [""])[-1] if payload.get("tips") else "")
    run = Run(
        id=text_field(payload.get("source_run_id"), oid),
        status=RunStatus(payload.get("status", "running")),
        graph=graph,
        refs=refs,
        transcript=transcript_blob(repo, transcript_id),
        manifest=blob_json(repo, manifest_id) if manifest_id else {},
        policies=blob_json(repo, policy_id) if policy_id else {},
        cache=blob_json(repo, cache_id) if cache_id else {},
        created_at=float(payload.get("created_at") or 0),
    )
    for attribute, field in (("system_prompt", "system_blob"), ("user_prompt", "prompt_blob")):
        blob = payload.get(field)
        setattr(run, attribute, repo.get(blob).body.decode(errors="replace") if blob else "")
    # text_field, not `or`: the v3 side constrains neither field, while the .tine
    # side requires both to be strings, so an unchecked int or dict here loaded a
    # run that could never be exported again. Manifest and payload stay verbatim.
    named = as_mapping(run.manifest.get("model")).get("name")
    run.model_info = text_field(payload.get("model"), named)
    run.metadata, tags = load_run_annotation(repo, oid)
    for tag in tags:
        run.add_tag(tag)
    run._v3_causal_ids = causal_ids
    run._v3_payload = dict(payload)
    run._v3_run_id = oid
    return run
