"""Causal state slicing for immutable repository forks."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentine._canon import _redact
from opentine._graph_analysis import _causal_transcript, _slice_pricing
from opentine._jsonsafe import json_safe
from opentine._unicode_text import assert_unicode_text
from opentine.repository._run_blobs import (
    LEGACY_MIGRATION_FIELDS,
    blob_json,
    json_blob,
    put_transcript,
    transcript_blob,
)
from opentine.repository._run_graph import filtered_legacy_refs, graph_tips
from opentine.repository._shallow_read import ShallowBoundary, shallow_cut_error
from opentine.repository._traversal import TraversalQueue

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


def _closure(repo: Repo, from_event: str, operation: str) -> set[str]:
    keep: set[str] = set()
    boundary = ShallowBoundary(repo)
    queue = TraversalQueue(((from_event, 0),))
    for event, _ in queue:
        if boundary.cuts(event):
            # A fork rewrites events/roots/tips from this closure, so stopping
            # here would silently drop real ancestry; refuse like load_run does.
            raise shallow_cut_error(operation, event)
        keep.add(event)
        payload = repo.get(event).payload()
        for dependency in [
            *(payload.get("parent_ids") or []),
            *(payload.get("causal_ids") or []),
        ]:
            queue.add(dependency)
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
    if raw is not None and not hasattr(raw, "items"):
        # The container's own shape, the one this function never checked: every
        # wrong *value* below is a typed refusal, while a wrong mapping raised a
        # bare AttributeError out of the comprehension. Duck-typed, not
        # isinstance(dict), so a MappingProxyType or other Mapping that works
        # today keeps working.
        raise ValueError("fork overrides must be an object")
    values = {key: value for key, value in (raw or {}).items() if value is not None}
    if any(not isinstance(key, str) for key in values):
        # Checked before the join below, which is where a non-str name actually
        # landed: reporting the unknown names raised TypeError instead of the
        # ValueError it was written to raise.
        raise ValueError("fork override names must be strings")
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
    if "prompt" in values:
        # The text rule belongs on this leg, not on Recorder.fork alone. Repo.fork
        # is public and MCP's fork_run_v3 calls it directly, so the raw blob encode
        # in fork_payload was still reachable with a str UTF-8 cannot spell and
        # surfaced a bare UnicodeEncodeError naming a byte offset instead of the
        # typed, path-bearing refusal every other write leg now produces. Checked
        # verbatim because the prompt is stored as a raw blob -- the one override
        # redaction never sees, so what is checked must be what is encoded.
        assert_unicode_text({"prompt": values["prompt"]}, where="fork override")
    # Every *other* override reaches the store through guarded_redaction, so it is
    # checked in that writer's own order -- json_safe's coercion, then the _redact
    # that may legitimately drop an unencodable credential-shaped policy value.
    # Checking the raw values instead would refuse a fork the blob writer accepts.
    # Written over the whole mapping so an override added above is covered here
    # without a second edit, and before _closure so nothing is written at all.
    assert_unicode_text(
        _redact(json_safe({key: item for key, item in values.items() if key != "prompt"})),
        where="fork override",
    )
    return values


def fork_payload(
    repo: Repo,
    source_id: str,
    payload: dict[str, Any],
    from_event: str,
    overrides: dict[str, Any] | None,
) -> dict[str, Any]:
    applied = _overrides(overrides)
    keep = _closure(repo, from_event, f"forking run {source_id}")
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
    for field in LEGACY_MIGRATION_FIELDS:
        forked.pop(field, None)
    if model:
        forked["model"] = model
    return forked
