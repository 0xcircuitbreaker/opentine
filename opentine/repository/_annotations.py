"""Deterministic mutable annotation heads for compatibility runs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentine._canon import _redact
from opentine._jsonsafe import json_safe
from opentine.kernel import KernelError, ObjectEnvelope, parse_oid
from opentine.redaction import redact_value

if TYPE_CHECKING:
    from opentine.repository.store import Repo

MAX_LEGACY_OBJECTS = 100_000
_COMPATIBILITY = "run-metadata-v1"


def validate_annotation_chain(repo: Repo, envelope: ObjectEnvelope) -> None:
    if envelope.object_type != "annotation":
        return
    payload = envelope.payload()
    previous_id = payload.get("previous_id")
    if not previous_id:
        return
    try:
        record = getattr(repo, "annotation_record", None)
        if callable(record):
            recorded = record(previous_id)
            if not isinstance(recorded, tuple) or len(recorded) != 2:
                raise KernelError("annotation previous object is malformed")
            object_type, target_id = recorded
            if object_type != "annotation":
                raise KernelError("annotation previous object must be an annotation")
            if target_id != payload.get("target_id"):
                raise KernelError("annotation versions must target the same object")
            return
        lookup = getattr(repo, "cached_envelope", None)
        previous = (
            lookup(previous_id)
            if callable(lookup)
            else ObjectEnvelope.decode(repo.raw(previous_id), previous_id)
        )
    except (KeyError, OSError) as exc:
        raise KernelError(f"annotation previous object is unavailable: {previous_id}") from exc
    try:
        prior = previous.payload()
    except KernelError:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise KernelError("annotation previous object is malformed") from exc
    if (
        previous.object_type != "annotation"
        or not isinstance(prior, dict)
        or prior.get("target_id") != payload.get("target_id")
    ):
        raise KernelError("annotation versions must target the same object")


def annotation_ref(run_id: str) -> str:
    object_type, digest = parse_oid(run_id)
    if object_type != "run":
        raise ValueError("compatibility annotations require a run id")
    return f"annotations/{digest}"


def _value(payload: Any, run_id: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("target_id") != run_id:
        raise ValueError("run annotation targets the wrong object")
    value = payload.get("value")
    if not isinstance(value, dict) or not isinstance(value.get("metadata", {}), dict):
        raise ValueError("run annotation value is malformed")
    tags = value.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError("run annotation tags are malformed")
    return value


def _bounded_legacy_oids(oids):
    try:
        yield from oids
    except ValueError as exc:
        if "typed object scan exceeds" in str(exc):
            raise ValueError("legacy annotation scan exceeds its object limit") from exc
        raise


def _legacy_head(repo: Repo, run_id: str) -> str | None:
    from opentine.repository._objects import iter_typed_object_oids
    from opentine.repository._semantic_view import semantic_view

    candidates: dict[str, dict[str, Any]] = {}
    typed = getattr(repo, "iter_typed_oids", None)
    path = getattr(repo, "path", None)
    if callable(typed):
        oids = typed({"annotation"}, limit=MAX_LEGACY_OBJECTS)
    elif path is not None:
        oids = iter_typed_object_oids(
            path,
            {"annotation"},
            limit=MAX_LEGACY_OBJECTS,
        )
    else:
        oids = (
            oid for oid in repo.iter_oids(limit=MAX_LEGACY_OBJECTS) if oid.startswith("annotation:")
        )
    view = semantic_view(repo)
    for index, oid in enumerate(_bounded_legacy_oids(oids), 1):
        if index > MAX_LEGACY_OBJECTS:
            raise ValueError("legacy annotation scan exceeds its object limit")
        payload = view.get(oid).payload()
        if isinstance(payload, dict) and payload.get("target_id") == run_id:
            candidates[oid] = payload
    marked = {
        oid: payload
        for oid, payload in candidates.items()
        if payload.get("compatibility") == _COMPATIBILITY
    }
    if marked:
        candidates = marked
    if not candidates:
        return None
    previous = {
        payload.get("previous_id")
        for payload in candidates.values()
        if payload.get("previous_id") in candidates
    }
    tips = sorted(set(candidates) - previous)
    if len(tips) != 1:
        raise ValueError("run has ambiguous unheaded legacy annotations")
    return tips[0]


def _resolved_head(repo: Repo, run_id: str) -> tuple[str | None, str | None]:
    ref = repo.read_ref(annotation_ref(run_id))
    if ref:
        return ref, ref
    return _legacy_head(repo, run_id), None


def load_run_annotation(repo: Repo, run_id: str) -> tuple[dict[str, Any], list[str]]:
    head, _ = _resolved_head(repo, run_id)
    if not head:
        return {}, []
    value = _value(repo.get(head).payload(), run_id)
    return dict(value.get("metadata") or {}), list(value.get("tags") or [])


def _assert_writable(value: Any) -> None:
    """Reject at write the annotation shapes ``_value`` rejects at read.

    ``put_run`` accepted a run whose tags held a non-string or whose metadata was
    not a mapping, then every later ``load_run`` raised — with fsck green. Write
    must be as strict as read.
    """
    if not isinstance(value, dict) or not isinstance(value.get("metadata", {}), dict):
        raise ValueError("run metadata must be a JSON object; fix run.metadata before saving")
    tags = value.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError("run tags must all be strings; fix run.tags before saving")


def _head_value(repo: Repo, head: str, run_id: str) -> dict[str, Any] | None:
    """Read the existing head for deduplication, tolerating a poisoned one.

    A malformed head must compare as not-a-duplicate so a corrected annotation
    can supersede it; raising here made repair through the API impossible.
    """
    try:
        return _value(repo.get(head).payload(), run_id)
    except ValueError:
        return None


def write_run_annotation(
    repo: Repo, run_id: str, metadata: dict[str, Any], tags: list[str]
) -> str | None:
    name = annotation_ref(run_id)
    old, ref_head = _resolved_head(repo, run_id)
    if old and old != ref_head:
        repo.update_ref(name, old, expected_old=ref_head)
        ref_head = old
    value = redact_value(_redact(json_safe({"metadata": metadata, "tags": tags})))
    _assert_writable(value)
    if old and _head_value(repo, old, run_id) == value:
        return old
    if old is None and not any(value.values()):
        return None
    oid = repo.put(
        "annotation",
        {
            "compatibility": _COMPATIBILITY,
            "previous_id": old,
            "target_id": run_id,
            "value": value,
        },
        redact=False,
    )
    repo.update_ref(name, oid, expected_old=ref_head)
    return oid
