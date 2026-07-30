"""Legacy .tine v2 serialization kept outside graph semantics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import opentine._artifact_shapes as artifact_shapes
from opentine._artifact_io import (  # fmt: skip  # fmt: skip
    artifact_digest,
    artifact_integrity,
    assert_loadable,
    read_artifact_json,
)
from opentine._canon import (
    FORMAT_VERSION,
    SUPPORTED_VERSIONS,
    _integrity_digest,
    _redact,
    atomic_write_text,
)  # fmt: skip
from opentine._graph_run import _usage
from opentine._graph_types import Graph, IntegrityResult, RunStatus, Step, StepKind
from opentine.migrations import LEGACY_VERSION, MigrationError, detect_version, migrate_dict


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
    )


def graph_from_dict(data: dict[str, Any]) -> Graph:
    graph = Graph()
    for record in artifact_shapes.ordered_step_records(data):
        graph.add(step_from_dict(record))
    return graph


def run_to_dict(run, *, redact: bool = False) -> dict[str, Any]:
    data = {
        "cache": dict(run.cache),
        "created_at": run.created_at,
        "format_version": run.format_version,
        "graph": {
            "order": list(run.graph.order),
            "steps": {step_id: step_to_dict(step) for step_id, step in run.graph.steps.items()},
        },
        "manifest": dict(run.manifest),
        "metadata": {
            **run.metadata,
            "model_info": run.model_info,
            "system_prompt": run.system_prompt,
            "user_prompt": run.user_prompt,
        },
        "policies": dict(run.policies),
        "refs": dict(run.refs),
        "run_id": run.id,
        "status": run.status.value,
        "transcript": list(run.transcript),
    }
    data["metadata"].pop("tags", None)
    if run.tags:
        data["metadata"]["tags"] = list(run.tags)
    return _redact(data) if redact else data


def run_from_dict(data: dict[str, Any], run_class):
    run = run_class(
        run_id=data["run_id"],
        status=RunStatus(data.get("status", "running")),
        graph=graph_from_dict(artifact_shapes.validate_run_record(data).get("graph", {})),
        refs=data.get("refs", {}),
        transcript=data.get("transcript", []),
        manifest=data.get("manifest", {}),
        policies=data.get("policies", {}),
        cache=data.get("cache", {}),
        metadata=data.get("metadata", {}),
        created_at=data.get("created_at", 0),
        format_version=data.get("format_version", FORMAT_VERSION),
    )
    # validate_run_record permits manifest.model = null and .get("model", {}) does not rescue an
    # explicit null, so the loader tracebacked on a validator-accepted file, killing every command.
    model = run.manifest.get("model")
    name = model.get("name") if isinstance(model, dict) else None
    run.model_info = name if isinstance(name, str) else run.metadata.get("model_info", "")
    run.system_prompt = run.metadata.get("system_prompt", "")
    run.user_prompt = run.metadata.get("user_prompt", "")
    return run


def save_run(
    run, path: str | Path, *, draft: bool = False, fsync: bool = False,
    sign_key: Any | None = None, sign_algorithm: str = "hmac-sha256",
    key_id: str | None = None, signer: str | None = None, signed_at: str | None = None,
) -> Path:  # fmt: skip
    target = Path(path)
    is_repo = target.is_dir() and (
        (target / "config.json").is_file() or (target / ".tine" / "config.json").is_file()
    )
    if is_repo:
        if sign_key is not None or draft:
            from opentine.signing import SignatureError

            raise SignatureError("repository targets do not support signing/draft; use attestation")
        from opentine.repo import Repo

        Repo.open(target).put_run(run, ref="heads/main")
        return target
    if sign_key is not None:
        from opentine.signing import SignatureError

        if draft:
            raise SignatureError("refusing to sign a draft checkpoint")
        if run.status not in (RunStatus.completed, RunStatus.failed):
            raise SignatureError(f"refusing to sign a non-terminal run (status={run.status.value})")
    data = run_to_dict(run, redact=True)
    if draft:
        data["draft"] = True
        data["metadata"]["autosave"] = {
            "partial": True,
            "status": run.status.value,
            "step_count": len(run.steps),
        }
    else:
        data["metadata"].pop("autosave", None)
    data["metadata"]["integrity"] = {"algorithm": "sha256", "digest": _integrity_digest(data)}
    if sign_key is not None:
        from opentine.signing import sign_artifact

        data["metadata"]["integrity"]["signature"] = sign_artifact(
            data,
            sign_key,
            algorithm=sign_algorithm,
            key_id=key_id,
            signer=signer,
            signed_at=signed_at,
        )
    serialized = json.dumps(data, indent=2, sort_keys=True, allow_nan=False)
    assert_loadable(serialized)  # never persist what this build could not read back
    atomic_write_text(target, serialized, fsync=fsync)
    return target


def load_run(path: str | Path, run_class):
    source = Path(path)
    is_repo = source.is_dir() and (
        (source / "config.json").is_file() or (source / ".tine" / "config.json").is_file()
    )
    if is_repo:
        from opentine.repo import Repo

        return Repo.open(source).load_run("heads/main")
    data = read_artifact_json(source)
    if not isinstance(data, dict):
        raise ValueError(".tine artifact root must be an object")
    try:
        version = detect_version(data)
    except MigrationError:
        version = None
    if version is None or version not in (LEGACY_VERSION, *SUPPORTED_VERSIONS):
        found = data.get("format_version", "missing")
        raise ValueError(
            f"Unsupported .tine format_version={found!r}; supported {SUPPORTED_VERSIONS}"
        )
    if version != FORMAT_VERSION:
        data = migrate_dict(data, FORMAT_VERSION)
    return run_from_dict(data, run_class)


def verify_integrity(path_or_data: str | Path | dict[str, Any]) -> IntegrityResult:
    try:
        data = path_or_data if isinstance(path_or_data, dict) else read_artifact_json(path_or_data)
    except FileNotFoundError:
        return IntegrityResult(False, None, None, None, "file not found")
    except OSError as exc:
        return IntegrityResult(False, None, None, None, f"read error: {exc}")
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        reason = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
        return IntegrityResult(False, None, None, None, f"invalid artifact: {reason}")
    if not isinstance(data, dict):
        return IntegrityResult(False, None, None, None, "artifact root is not an object")
    version = data.get("format_version")
    if type(version) is not int or version not in SUPPORTED_VERSIONS:
        found = version if version is not None else "missing"
        reason = f"unsupported .tine format_version={found!r}; supported {SUPPORTED_VERSIONS}"
        if isinstance(version, int) and not isinstance(version, bool) and version > FORMAT_VERSION:
            reason = f"unsupported .tine format_version={found}; written by a newer opentine"
        return IntegrityResult(False, None, None, None, reason)
    integrity = artifact_integrity(data)
    if not isinstance(integrity, dict):
        return IntegrityResult(False, None, None, None, "missing integrity digest")
    algorithm, expected = integrity.get("algorithm"), integrity.get("digest")
    if algorithm != "sha256":
        return IntegrityResult(False, str(algorithm), expected, None, "unsupported algorithm")
    try:
        valid_digest = isinstance(expected, str) and len(expected) == 64
        if valid_digest:
            int(expected, 16)
    except ValueError:
        valid_digest = False
    if not valid_digest:
        return IntegrityResult(False, "sha256", expected, None, "malformed digest")
    actual = artifact_digest(data)
    return IntegrityResult(
        actual == expected,
        "sha256",
        expected,
        actual,
        "ok" if actual == expected else "digest mismatch",
        bool(data.get("draft")),
    )
