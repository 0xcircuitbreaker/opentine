"""Pack reachability: the object graph first, then each run's associations.

Annotations and attestations name a run by ``target_id``; nothing links *to* them,
so a pack finds them by reverse lookup. Reachability used to interleave that
lookup with the graph walk under one object budget, so associations could make a
pack fail outright: a writer able to attach a thousand attestations each to ten
runs -- or to one run with nine thousand events -- left that history impossible
to fetch, clone or push. The graph is now walked first, under the budget as
before; associations are then added run by run, in discovery order, only while
they fit in what the graph left. A run whose associations do not all fit keeps
its annotations (its metadata) if those fit, and the run is reported as
*omitted* so a transfer can say so. Associations never make a pack fail.
"""

from __future__ import annotations

from typing import Any

from opentine.kernel import KernelError, validate_links
from opentine.repository._associations import associated_map
from opentine.repository._traversal import TraversalQueue


class OverBudget(KernelError):
    """The walk would exceed the pack object budget."""


def walk(
    repo: Any,
    start: list[str],
    seen: set[str],
    depth: int | None,
    limit: int,
) -> tuple[set[str], list[str]]:
    """Objects reachable from *start* that are not in *seen*, and the runs among them.

    *seen* is not modified; the walk refuses (``OverBudget``) once *seen* plus the
    new objects would exceed *limit*.
    """
    queue = TraversalQueue((oid, 0) for oid in start if oid not in seen)
    added: set[str] = set()
    runs: list[str] = []
    for oid, event_depth in queue:
        if not repo.has(oid):
            continue
        if oid not in added:
            if len(seen) + len(added) >= limit:
                raise OverBudget("pack graph exceeds maximum object count")
            added.add(oid)
        envelope = repo.get(oid)
        links = list(validate_links(envelope))
        if envelope.object_type == "run":
            runs.append(oid)
            if depth is not None:
                payload = envelope.payload()
                event_links = set(payload.get("events") or [])
                tips = payload.get("tips", [])
                links = [link for link in links if link not in event_links or link in tips]
        for link in links:
            if link in seen:
                continue
            next_depth = event_depth + (1 if link.startswith("event:") else 0)
            if depth is None or next_depth <= depth or not link.startswith("event:"):
                queue.add(link, next_depth, front=not link.startswith("event:"))
    return added, runs


def _related(repo: Any, run: str, limit: int) -> list[str] | None:
    try:
        return sorted(associated_map(repo, [run], limit).get(run, []))
    except (KernelError, ValueError):
        return None  # more associations than any pack could carry


def include_associations(
    repo: Any,
    runs: list[str],
    seen: set[str],
    depth: int | None,
    limit: int,
    omitted: list[str] | None,
) -> None:
    """Add each run's associations to *seen* while they fit; record runs left short."""
    checked: set[str] = set()
    position = 0
    while position < len(runs):
        run = runs[position]
        position += 1
        if run in checked:
            continue
        checked.add(run)
        related = _related(repo, run, limit)
        subsets = []
        if related is not None:
            subsets = [related, [oid for oid in related if oid.startswith("annotation:")]]
        complete = False
        for index, subset in enumerate(subsets):
            fresh = [oid for oid in subset if oid not in seen]
            if len(seen) + len(fresh) > limit:
                continue
            try:
                added, found = walk(repo, fresh, seen, depth, limit)
            except OverBudget:
                continue
            seen |= added
            runs.extend(found)
            complete = index == 0 or len(subset) == len(related or ())
            break
        if not complete and omitted is not None and run not in omitted:
            omitted.append(run)
