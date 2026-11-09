"""The stored-object reader ops the pyz answers case by case (0.50 parity).

``links.extract``, ``event.metrics``, ``run.graph``, ``annotation.chain`` and
``object.load`` (SPEC 1.5.6 and Part 6 items 3-5): one stored envelope checked
against the objects the case supplies (``args.objects``, base64 envelopes;
``args.present`` and ``args.shallow``, oids known to exist). These are the
checks a reader applies to an object it loads, so the pyz answers them with
the vendored kernel and a port of ``repository._run_graph`` and
``_annotations``; it still never opens a repository on disk.
"""

from __future__ import annotations

import base64
import math
from decimal import Decimal, InvalidOperation
from typing import Any

from .. import kernel

_RUN_STATUSES = {"running", "paused", "completed", "failed"}
_TOKEN_USAGE = {"input", "output", "cache_read", "cache_write_5m", "cache_write_1h", "reasoning",
                "total"}  # fmt: skip
_MAX_SAFE_INTEGER = 2**53 - 1


def _meter(value: Any, label: str, *, nonnegative: bool = True) -> None:
    try:
        if isinstance(value, str) and len(value) > 128:
            raise InvalidOperation
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise kernel.KernelError(f"{label} must be finite and non-negative") from exc
    if isinstance(value, bool) or not number.is_finite() or (nonnegative and number < 0):
        raise kernel.KernelError(f"{label} must be finite and non-negative")
    if not math.isfinite(float(number)):
        raise kernel.KernelError(f"{label} must be finite and non-negative")


def _event_metrics(envelope: kernel.ObjectEnvelope) -> None:
    if envelope.object_type != "event":
        return
    payload = envelope.payload()
    for field in ("cost", "duration"):
        _meter(payload.get(field, 0), f"event {field}")
    if "time_unix" in payload:
        _meter(payload["time_unix"], "event time_unix", nonnegative=False)
    usage = payload.get("usage") or {}
    if not isinstance(usage, dict):
        raise kernel.KernelError("event usage must be a mapping")
    for name, value in usage.items():
        if not isinstance(name, str) or type(value) not in {int, float}:
            raise kernel.KernelError(f"event usage.{name} must be numeric")
        _meter(value, f"event usage.{name}")
        number = Decimal(str(value))
        if name in _TOKEN_USAGE and (
            number != number.to_integral_value() or number > _MAX_SAFE_INTEGER
        ):
            raise kernel.KernelError(f"event usage.{name} must be a safe integer token count")


def _run_graph(stored: dict[str, bytes], envelope: kernel.ObjectEnvelope, present: set) -> None:
    """``repository._run_graph.validate_run_graph`` over the supplied objects."""
    if envelope.object_type != "run":
        return
    payload = envelope.payload()
    if payload.get("status", "running") not in _RUN_STATUSES:
        raise kernel.KernelError("run status is invalid")
    if "parents" in payload:
        parents = payload["parents"]
        if (
            type(parents) is not list
            or not 1 <= len(parents) <= 64
            or len(set(parents)) != len(parents)
            or any(kernel.parse_oid(parent)[0] != "run" for parent in parents)
        ):
            raise kernel.KernelError(
                "parents must be a non-empty list of unique run ids (omit when none)"
            )
    events = list(payload.get("events") or [])
    event_set, positions = set(events), {oid: index for index, oid in enumerate(events)}
    legacy = payload.get("legacy_refs", {})
    if not isinstance(legacy, dict) or any(
        not isinstance(n, str) or not isinstance(t, str) or t not in event_set
        for n, t in legacy.items()
    ):
        raise kernel.KernelError("legacy_refs must map names to events in the run")
    graph: dict[str, list[str]] = {}
    complete = all(oid in stored or oid in present for oid in events)
    for event_id in events:
        if event_id not in stored:
            if event_id in present:  # known to exist, but its bytes were not supplied
                raise KeyError(event_id)
            continue
        event = kernel.ObjectEnvelope.decode(stored[event_id], event_id)
        if event.object_type != "event":
            raise kernel.KernelError("run events must resolve to event objects")
        values = list(event.payload().get("parent_ids") or [])
        causal = list(event.payload().get("causal_ids") or [])
        if any(parent not in event_set for parent in values):
            raise kernel.KernelError(f"run event has a parent outside its event graph: {event_id}")
        if any(link not in event_set for link in causal):
            raise kernel.KernelError(
                f"run event has a causal link outside its event graph: {event_id}"
            )
        if any(positions[link] >= positions[event_id] for link in [*values, *causal]):
            raise kernel.KernelError("run events must be in parent-before-child/dependency order")
        graph[event_id] = values
    if not complete:
        return
    if set(payload.get("roots") or []) != {oid for oid, values in graph.items() if not values}:
        raise kernel.KernelError("run roots do not match parentless events")
    tips = event_set - {parent for values in graph.values() for parent in values}
    if set(payload.get("tips") or []) != tips:
        raise kernel.KernelError("run tips do not match event-graph leaves")


def _annotation_chain(stored: dict[str, bytes], envelope: kernel.ObjectEnvelope) -> None:
    if envelope.object_type != "annotation":
        return
    payload = envelope.payload()
    previous_id = payload.get("previous_id")
    if not previous_id:
        return
    if previous_id not in stored:
        raise kernel.KernelError(f"annotation previous object is unavailable: {previous_id}")
    previous = kernel.ObjectEnvelope.decode(stored[previous_id], previous_id)
    prior = previous.payload()
    if (
        previous.object_type != "annotation"
        or not isinstance(prior, dict)
        or prior.get("target_id") != payload.get("target_id")
    ):
        raise kernel.KernelError("annotation versions must target the same object")


def _store(args: dict) -> tuple[dict[str, bytes], Any]:
    """The supplied envelopes by oid, and SPEC 1.5.6's ``exists`` (``None``: no check)."""
    stored: dict[str, bytes] = {}
    for encoded in args.get("objects") or []:
        data = base64.b64decode(encoded, validate=True)
        stored[kernel.ObjectEnvelope.decode(data).oid] = data
    if not any(key in args for key in ("present", "objects", "shallow")):
        return stored, None
    known = set(args.get("present") or []) | set(stored) | set(args.get("shallow") or [])
    return stored, known.__contains__


def _present(args: dict) -> set[str]:
    return set(args.get("present") or [])


def object_load(raw: Any, value: Any, args: dict) -> dict:
    stored, exists = _store(args)
    envelope = kernel.ObjectEnvelope.decode(raw, args.get("expected_oid"))
    links = kernel.validate_links(envelope, exists)
    _event_metrics(envelope)
    _run_graph(stored, envelope, _present(args))
    _annotation_chain(stored, envelope)
    return {"oid": envelope.oid, "links": sorted(links)}


def links_extract(raw: Any, value: Any, args: dict) -> dict:
    exists = _store(args)[1]
    return {"links": sorted(kernel.validate_links(kernel.ObjectEnvelope.decode(raw), exists))}


def event_metrics(raw: Any, value: Any, args: dict) -> dict:
    _event_metrics(kernel.ObjectEnvelope.decode(raw))
    return {}


def run_graph(raw: Any, value: Any, args: dict) -> dict:
    _run_graph(_store(args)[0], kernel.ObjectEnvelope.decode(raw), _present(args))
    return {}


def annotation_chain(raw: Any, value: Any, args: dict) -> dict:
    _annotation_chain(_store(args)[0], kernel.ObjectEnvelope.decode(raw))
    return {}


OPS = {
    "links.extract": links_extract,
    "event.metrics": event_metrics,
    "run.graph": run_graph,
    "annotation.chain": annotation_chain,
    "object.load": object_load,
}

__all__ = ["OPS"]
