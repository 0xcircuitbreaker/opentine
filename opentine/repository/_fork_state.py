"""Causal state slicing for immutable repository forks."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentine._graph_analysis import _causal_transcript, _slice_pricing
from opentine.repository._run_blobs import blob_json, json_blob, put_transcript, transcript_blob
from opentine.repository._run_graph import filtered_legacy_refs, graph_tips

if TYPE_CHECKING:
    from opentine.repository.store import Repo

_FORK_FIELDS = {"created_at", "prompt_blob", "session_id", "system_blob"}
_FORK_MANIFESTS = {
    "budget",
    "cache",
    "code",
    "environment",
    "policy",
    "pricing",
    "run",
    "transcript",
}


def _closure(repo: Repo, from_event: str) -> set[str]:
    keep: set[str] = set()
    queue = [from_event]
    while queue:
        event = queue.pop()
        if event in keep:
            continue
        keep.add(event)
        payload = repo.get(event).payload()
        queue.extend(payload.get("parent_ids") or [])
        queue.extend(payload.get("causal_ids") or [])
    return keep


def _retained_model(repo: Repo, events: list[str]) -> str | None:
    for event in reversed(events):
        model = repo.get(event).payload().get("model")
        if isinstance(model, str) and model:
            return model
    return None


def _manifests(
    repo: Repo,
    manifests: dict[str, str],
    keep: set[str],
    from_event: str,
    model: str | None,
    policy: dict[str, Any] | None,
) -> dict[str, str]:
    result = {name: oid for name, oid in manifests.items() if name in _FORK_MANIFESTS}
    if transcript := manifests.get("transcript"):
        messages = _causal_transcript(transcript_blob(repo, transcript), keep, from_event)
        result["transcript"] = put_transcript(repo, messages, {oid: oid for oid in keep})
    if "cache" in manifests:
        result["cache"] = json_blob(repo, {})
    if policy is not None:
        result["policy"] = json_blob(repo, policy)
    if pricing_manifest := manifests.get("pricing"):
        wrapper = {"pricing": blob_json(repo, pricing_manifest)}
        _slice_pricing(wrapper, keep)
        result["pricing"] = json_blob(repo, wrapper["pricing"])
    if run_manifest := manifests.get("run"):
        value = blob_json(repo, run_manifest)
        value.pop("resume_history", None)
        _slice_pricing(value, keep)
        if isinstance(value.get("model"), dict):
            value["model"] = {**value["model"]}
            if model:
                value["model"]["name"] = model
            else:
                value["model"].pop("name", None)
        result["run"] = json_blob(repo, value)
    return result


def _overrides(raw: dict[str, Any] | None) -> dict[str, Any]:
    values = {key: value for key, value in (raw or {}).items() if value is not None}
    unknown = set(values) - {"model", "policy", "prompt", "resume"}
    if unknown:
        raise ValueError(f"unknown fork override(s): {', '.join(sorted(unknown))}")
    if "model" in values and (not isinstance(values["model"], str) or not values["model"]):
        raise ValueError("fork model override must be a non-empty string")
    if "prompt" in values and not isinstance(values["prompt"], str):
        raise ValueError("fork prompt override must be a string")
    if "policy" in values and not isinstance(values["policy"], dict):
        raise ValueError("fork policy override must be an object")
    if "resume" in values and not isinstance(values["resume"], bool):
        raise ValueError("fork resume override must be a boolean")
    return values


def fork_payload(
    repo: Repo,
    source_id: str,
    payload: dict[str, Any],
    from_event: str,
    overrides: dict[str, Any] | None,
) -> dict[str, Any]:
    applied = _overrides(overrides)
    keep = _closure(repo, from_event)
    events = [event for event in payload["events"] if event in keep]
    forked = {name: payload[name] for name in _FORK_FIELDS if name in payload}
    forked["events"] = events
    forked["legacy_refs"] = filtered_legacy_refs(payload, keep)
    model = applied.get("model") or _retained_model(repo, events)
    forked["manifests"] = _manifests(
        repo,
        payload.get("manifests") or {},
        keep,
        from_event,
        model,
        applied.get("policy"),
    )
    recorded: dict[str, Any] = {}
    if model and "model" in applied:
        recorded["model"] = model
    if "prompt" in applied:
        forked["prompt_blob"] = repo.put("blob", applied["prompt"].encode())
        recorded["prompt_blob"] = forked["prompt_blob"]
    if "policy" in applied:
        recorded["policy_manifest"] = forked["manifests"]["policy"]
    if applied.get("resume"):
        recorded["resume"] = True
    forked["fork_overrides"] = recorded
    forked["forked_from"] = source_id
    forked["roots"] = [event for event in payload.get("roots", []) if event in keep]
    forked["status"] = "running"
    forked["tips"] = graph_tips(repo, events)
    forked.pop("finished_at", None)
    for field in (
        "legacy_blob",
        "legacy_format",
        "legacy_verification",
        "migration_map_blob",
        "signature_scope",
    ):
        forked.pop(field, None)
    if model:
        forked["model"] = model
    return forked
