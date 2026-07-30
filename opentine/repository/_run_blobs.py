"""Canonical redacted blobs used by compatibility Run conversion."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentine._blob_guard import guarded_blob_body, guarded_blob_parse
from opentine._jsonsafe import json_safe

if TYPE_CHECKING:
    from opentine.repository.store import Repo


def json_blob(repo: Repo, value: Any) -> str:
    return repo.put("blob", guarded_blob_body(value), redact=False)


def blob_json(repo: Repo, oid: str) -> dict[str, Any]:
    # Reader and writer are the paired halves of one contract; keeping both in
    # _blob_guard is what stops a rule from drifting onto one side only.
    return guarded_blob_parse(repo.get(oid).body)


def transcript_blob(repo: Repo, oid: str | None) -> list[Any]:
    if not oid:
        return []
    messages = blob_json(repo, oid).get("messages")
    if not isinstance(messages, list):
        raise ValueError("compatibility transcript must be a list")
    return messages


def run_origin(repo: Repo, run: Any) -> dict[str, Any]:
    fork_base = getattr(run, "_v3_fork_base", None)
    if fork_base is not None:
        source_id = getattr(run, "_v3_source_run_id", None)
        source_payload = getattr(run, "_v3_source_payload", None)
        if not isinstance(fork_base, dict) or not isinstance(source_id, str):
            raise ValueError("compatibility fork has malformed v3 provenance")
        try:
            stored = repo.get(source_id)
        except KeyError as exc:
            raise ValueError("cannot save a foreign v3 fork through this repository") from exc
        if not isinstance(source_payload, dict) or stored.payload() != source_payload:
            raise ValueError("compatibility fork source provenance does not match")
        base = dict(fork_base)
        stored_manifests = base.get("manifests") or {}
        if not isinstance(stored_manifests, dict):
            # dict(<truthy non-mapping>) raised the same bare TypeError the
            # unguarded pricing loop below did; provenance shape is this
            # function's own error to report.
            raise ValueError("compatibility fork has malformed v3 provenance")
        manifests = dict(stored_manifests)
        pricing_id = manifests.get("pricing")
        if pricing_id:
            from opentine._graph_analysis import _slice_pricing

            wrapper = {"pricing": blob_json(repo, pricing_id)}
            _slice_pricing(wrapper, {step.id for step in run.steps})
            manifests["pricing"] = json_blob(repo, wrapper["pricing"])
        base["manifests"] = manifests
        base["forked_from"] = source_id
        return base
    origin_id = getattr(run, "_v3_run_id", None)
    origin_payload = getattr(run, "_v3_payload", None)
    if origin_id is None and origin_payload is None:
        return {}
    if not isinstance(origin_id, str) or not isinstance(origin_payload, dict):
        raise ValueError("compatibility Run has malformed v3 provenance")
    try:
        stored = repo.get(origin_id)
    except KeyError as exc:
        raise ValueError("cannot save a foreign v3 Run through this repository") from exc
    if stored.object_type != "run" or stored.payload() != origin_payload:
        raise ValueError("compatibility Run v3 provenance does not match the repository")
    return dict(origin_payload)


def put_transcript(repo: Repo, messages: list[Any], event_map: dict[str, str]) -> str:
    if not isinstance(messages, list):
        # Same refusal transcript_blob raises on the read side. Iterating the
        # container blindly raised a bare TypeError on a scalar and silently
        # shredded a str into one turn per character.
        raise ValueError("compatibility transcript must be a list")
    mapped: list[Any] = []
    for item in messages:
        if not isinstance(item, dict):
            # Loading and forking tolerate non-dict transcript turns, so a run
            # that loads must also be writable; only dict turns carry step_ids.
            mapped.append(item)
            continue
        stored = dict(item)
        step = stored.get("step_id")
        if step is not None:
            if not isinstance(step, str) or step not in event_map:
                raise ValueError("compatibility transcript references an unknown step")
            stored["step_id"] = event_map[step]
        mapped.append(stored)
    return json_blob(repo, {"messages": mapped})


def put_run_manifest(repo: Repo, manifest: dict[str, Any], event_map: dict[str, str]) -> str:
    current_ids = set(event_map.values())

    def mapped(value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("pricing manifest step references must be strings")
        if value in event_map:
            return event_map[value]
        if value in current_ids:
            return value
        raise ValueError("pricing manifest references an unknown step")

    stored = json_safe(manifest)
    pricing = stored.get("pricing") if isinstance(stored, dict) else None
    if isinstance(pricing, dict):
        cards = pricing.get("rate_cards")
        if isinstance(cards, dict):
            pricing["rate_cards"] = {mapped(key): value for key, value in cards.items()}
        # Only a list can carry step references to remap. Any other container is
        # stored verbatim, exactly as a str/dict/None one already was: Run.load
        # does not constrain manifest.pricing, so refusing here would make a run
        # that loads unwritable. Iterating it blindly raised a bare TypeError out
        # of put_run and `tine migrate-v3` on a truthy scalar.
        invocations = pricing.get("invocations")
        for invocation in invocations if isinstance(invocations, list) else ():
            if isinstance(invocation, dict) and invocation.get("step_id") is not None:
                invocation["step_id"] = mapped(invocation["step_id"])
    return json_blob(repo, stored)
