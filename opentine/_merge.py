"""Deterministic run merge and pick over payloads (0.47, F2, SPEC 4.19).

A merge combines two runs, *ours* (``parents[0]``, the mainline) and *theirs*,
into one new run; it is defined over the two run payloads alone (and, when
both sides carry workspace trees, the three flattened trees), so the same
inputs give the same merge oid in every implementation:

1. **Events.** The events both runs hold (in ours' order), then ours' own,
   then theirs' own, then one ``merge`` event. Content addressing makes a
   shared event identical, and each side's order already puts parents first.
2. **The merge event** has ``parent_ids`` = the leaves of that union (ours'
   first), ``time_unix`` = the later ``created_at`` and an ``output_blob``
   holding ``{"type": "opentine.merge", "merged": [ours, theirs],
   "conflicts": [...]}``; with trees, ``tree`` is the three-way merge.
3. **The run** is ours' payload with ``events``, ``roots`` (both sides'),
   ``tips`` (the merge event), ``parents`` ``[ours, theirs]``, the later
   ``created_at`` and ``status`` (``paused`` with conflicts, else
   ``completed``); ``forked_from`` is dropped. Manifests are ours'; a
   differing ``policy`` manifest is a conflict.

A **pick** copies chosen events of another run onto ours' tips, in order,
each with ``picked_from`` naming the source event (:func:`pick_payloads`).
:mod:`opentine._merge_tree` holds the tree merge; the repository side is
:mod:`opentine.repository._merge_ops`.
"""

from __future__ import annotations

from typing import Any

from opentine._merge_tree import Flat, encode_trees, merge_flat
from opentine.kernel import KernelError, ObjectEnvelope, canonical_json, object_id

MERGE_KIND = "merge"
OUTPUT_TYPE = "opentine.merge"
_EMPTY_EVENT = {"billing": {}, "causal_ids": [], "cost": 0, "duration": 0, "error": {},
                "model": "", "tool": {}, "usage": {}}  # fmt: skip


class MergeError(ValueError):
    """A refused merge or pick; ``code`` is the conformance reason (``merge.*``)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def run_oid(payload: dict[str, Any]) -> str:
    return ObjectEnvelope.create("run", payload).oid


def _events(payload: Any, side: str) -> list[str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
        raise MergeError("merge.malformed", f"merge input is malformed: {side} is not a run")
    events = payload["events"]
    if not events or not all(isinstance(e, str) for e in events) or len(set(events)) != len(events):
        raise MergeError("merge.malformed", f"merge input is malformed: {side} events")
    for field in ("tips", "roots"):
        if not isinstance(payload.get(field), list) or not set(payload[field]) <= set(events):
            raise MergeError("merge.malformed", f"merge input is malformed: {side} {field}")
    return events


def _uniq(rows: list[str]) -> list[str]:
    return list(dict.fromkeys(rows))


def _when(*payloads: dict[str, Any]) -> int | float:
    values = [p.get("created_at") for p in payloads]
    numbers = [v for v in values if isinstance(v, int | float) and not isinstance(v, bool)]
    return max(numbers) if numbers else 0


def leaves(ours: dict[str, Any], theirs: dict[str, Any]) -> list[str]:
    """The leaves of the union of two runs' event graphs (ours' tips first).

    A run's tips are exactly its leaves, so a tip of one side that the other
    side holds as a non-tip has a child there and is no leaf of the union.
    """
    inner = {e for side in (ours, theirs) for e in side["events"] if e not in side["tips"]}
    return [e for e in _uniq([*ours["tips"], *theirs["tips"]]) if e not in inner]


def blob_oid(value: dict[str, Any]) -> tuple[str, bytes]:
    body = canonical_json(value)
    return object_id("blob", 1, body), body


def merge_payloads(
    ours: dict[str, Any],
    theirs: dict[str, Any],
    trees: dict[str, Flat | None] | None = None,
) -> dict[str, Any]:
    """The merge of *ours* and *theirs*: every object to write, and the oids.

    Returns ``{"run", "run_oid", "event", "event_oid", "blobs", "conflicts",
    "status", "tree"}``; ``blobs`` maps oid -> ``(schema, body)``.
    """
    ours_events, theirs_events = _events(ours, "ours"), _events(theirs, "theirs")
    ours_oid, theirs_oid = run_oid(ours), run_oid(theirs)
    if ours_oid == theirs_oid:
        raise MergeError("merge.same-run", "cannot merge a run with itself")
    if set(theirs_events) <= set(ours_events):
        raise MergeError("merge.up-to-date", "theirs is already contained in ours: up to date")
    in_theirs, in_ours = set(theirs_events), set(ours_events)
    common = [e for e in ours_events if e in in_theirs]
    union = [*common, *(e for e in ours_events if e not in in_theirs),
             *(e for e in theirs_events if e not in in_ours)]  # fmt: skip
    conflicts: list[dict[str, Any]] = []
    blobs: dict[str, tuple[int, bytes]] = {}
    tree = None
    trees = trees or {}
    if trees.get("ours") is not None and trees.get("theirs") is not None:
        try:
            flat, tree_conflicts = merge_flat(trees.get("base"), trees["ours"], trees["theirs"])
            tree, written = encode_trees(flat)
        except KernelError as exc:
            raise MergeError("merge.malformed", f"merge input is malformed: {exc}") from exc
        conflicts += tree_conflicts
        blobs.update({oid: (2, body) for oid, body in written.items()})
    mine, other = ours.get("manifests") or {}, theirs.get("manifests") or {}
    if mine.get("policy") != other.get("policy"):
        conflicts.append({"kind": "manifest", "name": "policy", "base": None,
                          "ours": mine.get("policy"), "theirs": other.get("policy")})  # fmt: skip
    output, body = blob_oid(
        {"conflicts": conflicts, "merged": [ours_oid, theirs_oid], "type": OUTPUT_TYPE}
    )
    blobs[output] = (1, body)
    at = _when(ours, theirs)
    event: dict[str, Any] = {**_EMPTY_EVENT, "kind": MERGE_KIND, "output_blob": output,
                             "parent_ids": leaves(ours, theirs), "time_unix": at}  # fmt: skip
    if tree is not None:
        event["tree"] = tree
    event_oid = ObjectEnvelope.create("event", event).oid
    status = "paused" if conflicts else "completed"
    run = {key: value for key, value in ours.items() if key not in ("forked_from", "parents")}
    run.update(events=[*union, event_oid], roots=_uniq([*ours["roots"], *theirs["roots"]]),
               tips=[event_oid], parents=[ours_oid, theirs_oid], created_at=at,
               status=status)  # fmt: skip
    return {"run": run, "run_oid": run_oid(run), "event": event, "event_oid": event_oid,
            "blobs": blobs, "conflicts": conflicts, "status": status, "tree": tree}  # fmt: skip


def pick_payloads(ours: dict[str, Any], picks: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    """Copy *picks* (``(source oid, event payload)``, in order) onto ours' tips.

    Each copy's ``parent_ids`` are the current tips, its ``causal_ids`` keep
    only links the new run holds (an earlier pick maps to its copy), and it
    names its source in ``picked_from``. Returns ``{"run", "run_oid",
    "events": [(oid, payload)], "map"}``.
    """
    events = _events(ours, "ours")
    if not picks:
        raise MergeError("merge.malformed", "pick needs at least one event")
    held, mapping = set(events), {}
    rows: list[str] = list(events)
    tips = list(ours["tips"])
    written: list[tuple[str, dict[str, Any]]] = []
    for source, payload in picks:
        if not isinstance(payload, dict) or source in held:
            raise MergeError("merge.malformed", f"cannot pick {source}: already in the run")
        if ObjectEnvelope.create("event", payload).oid != source:
            raise MergeError("merge.malformed", f"cannot pick {source}: payload is another event")
        if source in mapping:
            raise MergeError("merge.malformed", f"cannot pick {source} twice")
        links = payload.get("causal_ids") or []
        if not isinstance(links, list) or not all(isinstance(c, str) for c in links):
            raise MergeError("merge.malformed", f"cannot pick {source}: malformed causal_ids")
        causal = [mapping.get(c, c) for c in links]
        copy = {**payload, "parent_ids": tips, "picked_from": source,
                "causal_ids": _uniq([c for c in causal if c in held])}  # fmt: skip
        oid = ObjectEnvelope.create("event", copy).oid
        if oid in held:
            raise MergeError("merge.malformed", f"picking {source} adds nothing")
        mapping[source] = oid
        held.add(oid)
        rows.append(oid)
        tips = [oid]
        written.append((oid, copy))
    run = {key: value for key, value in ours.items() if key not in ("forked_from", "parents")}
    run.update(events=rows, tips=tips, forked_from=run_oid(ours))
    return {"run": run, "run_oid": run_oid(run), "events": written, "map": mapping}


__all__ = ["MERGE_KIND", "MergeError", "blob_oid", "leaves", "merge_payloads", "pick_payloads",
           "run_oid"]  # fmt: skip
