"""Conversion between compatibility ``Run`` objects and immutable v3 objects."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from opentine._canon import _redact
from opentine._jsonsafe import json_safe
from opentine.kernel import canonical_json
from opentine.redaction import redact_value

if TYPE_CHECKING:
    from opentine.graph import Run
    from opentine.repository.store import Repo

MAX_V2_ARTIFACT_BYTES = 256 * 1024 * 1024


def _read_v2(path: Path) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(MAX_V2_ARTIFACT_BYTES + 1)
    if len(raw) > MAX_V2_ARTIFACT_BYTES:
        raise ValueError("v2 artifact exceeds migration size limit")
    return raw


@dataclass(frozen=True)
class RunObjectResult:
    run_id: str
    event_map: dict[str, str]
    annotation_id: str | None = None


def _json_blob(repo: Repo, value: Any) -> str:
    redacted = redact_value(_redact(json_safe(value)))
    return repo.put("blob", canonical_json(redacted), redact=False)


def put_run(
    repo: Repo,
    run: Run,
    *,
    ref: str | None = None,
    legacy_blob: str | None = None,
    legacy_verification: dict[str, Any] | None = None,
) -> RunObjectResult:
    event_map: dict[str, str] = {}
    events: list[str] = []
    for step in run.steps:
        input_blob = _json_blob(repo, step.inputs)
        output_blob = _json_blob(repo, step.outputs)
        payload = {
            "billing": _redact(step.billing),
            "causal_ids": [],
            "cost": step.cost,
            "duration": step.duration,
            "error": _redact(step.error),
            "input_blob": input_blob,
            "kind": step.kind.value,
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
    tips = [event_map[tip] for tip in run.refs.values() if tip and tip in event_map]
    tips = list(dict.fromkeys(tips or ([events[-1]] if events else [])))
    manifests = {
        "run": _json_blob(repo, run.manifest),
        "policy": _json_blob(repo, run.policies),
    }
    migration_map_blob = _json_blob(repo, event_map) if legacy_blob else None
    payload: dict[str, Any] = {
        "created_at": run.created_at,
        "events": events,
        "manifests": manifests,
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
    annotation_id = None
    mutable = {"metadata": run.metadata, "tags": run.tags}
    if any(mutable.values()):
        annotation_id = repo.put(
            "annotation",
            {"previous_id": None, "target_id": run_id, "value": json_safe(mutable)},
        )
    if ref:
        old = repo.read_ref(ref)
        repo.update_ref(ref, run_id, expected_old=old)
    return RunObjectResult(run_id, event_map, annotation_id)


def _blob_json(repo: Repo, oid: str) -> dict[str, Any]:
    parsed = json.loads(repo.get(oid).body)
    return parsed if isinstance(parsed, dict) else {}


def load_run(repo: Repo, oid_or_ref: str) -> Run:
    from opentine.graph import Graph, Run, RunStatus, Step, StepKind

    oid = repo.read_ref(oid_or_ref) if not oid_or_ref.startswith("run:") else oid_or_ref
    if not oid:
        raise KeyError(oid_or_ref)
    payload = repo.get(oid).payload()
    if not isinstance(payload, dict):
        raise ValueError("run object payload is not a mapping")
    graph = Graph()
    for event_id in payload.get("events") or []:
        event = repo.get(event_id).payload()
        raw_kind = str(event.get("kind", "model"))
        legacy_kind = (
            StepKind(raw_kind) if raw_kind in StepKind._value2member_map_ else StepKind.model
        )
        graph.add(
            Step(
                id=event_id,
                parent_ids=list(event.get("parent_ids") or []),
                kind=legacy_kind,
                inputs=_blob_json(repo, event["input_blob"]) if event.get("input_blob") else {},
                outputs=_blob_json(repo, event["output_blob"]) if event.get("output_blob") else {},
                model_info=event.get("model", ""),
                tool_info={"v3_kind": raw_kind, **dict(event.get("tool") or {})},
                error=dict(event.get("error") or {}),
                timestamp=float(event.get("time_unix") or 0),
                duration=float(event.get("duration") or 0),
                cost=float(event.get("cost") or 0),
                usage=dict(event.get("usage") or {}),
                billing=dict(event.get("billing") or {}),
            )
        )
    manifest_id = (payload.get("manifests") or {}).get("run")
    policy_id = (payload.get("manifests") or {}).get("policy")
    refs = {"main": (payload.get("tips") or [""])[-1] if payload.get("tips") else ""}
    run = Run(
        id=payload.get("source_run_id") or oid,
        status=RunStatus(payload.get("status", "running")),
        graph=graph,
        refs=refs,
        manifest=_blob_json(repo, manifest_id) if manifest_id else {},
        policies=_blob_json(repo, policy_id) if policy_id else {},
        created_at=float(payload.get("created_at") or 0),
    )
    system_blob = payload.get("system_blob")
    prompt_blob = payload.get("prompt_blob")
    run.system_prompt = repo.get(system_blob).body.decode(errors="replace") if system_blob else ""
    run.user_prompt = repo.get(prompt_blob).body.decode(errors="replace") if prompt_blob else ""
    run.model_info = run.manifest.get("model", {}).get("name", "")
    annotations = [
        repo.get(candidate).payload()
        for candidate in repo.iter_oids()
        if candidate.startswith("annotation:")
        and repo.get(candidate).payload().get("target_id") == oid
    ]
    for annotation in annotations:
        value = annotation.get("value") or {}
        run.metadata.update(value.get("metadata") or {})
        for tag in value.get("tags") or []:
            run.add_tag(tag)
    return run


def migrate_v2(
    repo: Repo,
    path: str | Path,
    *,
    ref: str | None = None,
    hmac_key: bytes | None = None,
    public_key: Any | None = None,
    trust_embedded: bool = False,
    strict: bool = True,
) -> RunObjectResult:
    from opentine.graph import Run, _run_from_dict

    source = Path(path)
    raw = _read_v2(source)
    data = json.loads(raw)
    if data.get("format_version") != 2:
        raise ValueError("v3 repository migration requires a .tine v2 source")
    integrity = Run.verify_integrity(data)
    signature = Run.verify_signature(
        data,
        hmac_key=hmac_key,
        public_key=public_key,
        trust_embedded=trust_embedded,
    )
    if strict:
        from opentine.signing import SignatureError

        if not integrity.ok:
            raise SignatureError(f"refusing to migrate a tampered v2 artifact: {integrity.reason}")
        if (hmac_key or public_key or trust_embedded) and signature.state not in (
            "verified",
            "verified-tofu",
        ):
            raise SignatureError(
                f"refusing to migrate: signature not verified (state={signature.state})"
            )
    verification = {
        "integrity": asdict(integrity),
        "signature": asdict(signature),
        "scope": "original-v2-artifact",
    }
    legacy_blob = repo.put("blob", raw, redact=False)
    run = _run_from_dict(data)
    return put_run(
        repo,
        run,
        ref=ref,
        legacy_blob=legacy_blob,
        legacy_verification=verification,
    )
