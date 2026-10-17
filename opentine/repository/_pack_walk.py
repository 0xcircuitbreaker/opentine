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

from collections.abc import Callable
from typing import Any

from opentine.kernel import KernelError, validate_links
from opentine.repository._associations import associated_map, association_indexes
from opentine.repository._pack_work import FRAMING_RESERVE, Sizes, WorkBudget
from opentine.repository._traversal import TraversalQueue


class OverBudget(KernelError):
    """The walk would exceed the pack object budget."""


def walk(
    repo: Any,
    start: list[str],
    seen: set[str],
    depth: int | None,
    limit: int,
    charge: Callable[[str], None] | None = None,
    links_out: dict[str, tuple[str, ...]] | None = None,
) -> tuple[set[str], list[str]]:
    """Objects reachable from *start* that are not in *seen*, and the runs among them.

    *seen* is not modified; the walk refuses (``OverBudget``) once *seen* plus the
    new objects would exceed *limit*. *links_out*, when given, receives every
    added object's links (all of them, before any depth cut).
    """
    remaining = limit - len(seen)
    if remaining < 1:
        raise OverBudget("pack graph exceeds maximum object count")
    try:
        queue = TraversalQueue(((oid, 0) for oid in start if oid not in seen), limit=remaining)
    except KernelError as exc:
        raise OverBudget(str(exc)) from exc
    added: set[str] = set()
    runs: list[str] = []
    for oid, event_depth in queue:
        if not repo.has(oid):
            continue
        if oid not in added:
            if len(seen) + len(added) >= limit:
                raise OverBudget("pack graph exceeds maximum object count")
            if charge is not None:
                charge(oid)
            added.add(oid)
        envelope = repo.get(oid)
        links = list(validate_links(envelope))
        if links_out is not None:
            links_out[oid] = tuple(links)
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
                try:
                    queue.add(link, next_depth, front=not link.startswith("event:"))
                except KernelError as exc:
                    raise OverBudget(str(exc)) from exc
    return added, runs


def _related(repo: Any, run: str, limit: int, memo: dict[str, Any]) -> list[str] | None:
    # A local repository's target indexes are listed once per walk, not per run:
    # fetched associations would otherwise make every pack runs x objects.
    if "indexes" not in memo:
        memo["indexes"] = None
        if getattr(repo, "path", None) is not None and not callable(
            getattr(repo, "associated_oids", None)
        ):
            try:
                memo["indexes"] = association_indexes(repo)
            except (KernelError, ValueError):
                memo["indexes"] = False  # over the scan limit: every run is short
    if memo["indexes"] is False:
        return None
    try:
        return sorted(associated_map(repo, [run], limit, indexes=memo["indexes"]).get(run, []))
    except (KernelError, ValueError):
        return None  # more associations than any pack could carry


def include_associations(
    repo: Any,
    runs: list[str],
    seen: set[str],
    depth: int | None,
    limit: int,
    omitted: list[str] | None,
    max_body: int | None = None,
    links: dict[str, tuple[str, ...]] | None = None,
) -> None:
    """Add each run's associations to *seen* while they fit; record runs left short.

    "Fit" covers every bound the pack is later built under: the object count, the
    encoded body size (*max_body*), and the source budget of a semantic view. An
    association subset that would break any of them -- or fails to walk at all --
    is skipped, and the budget it charged is rolled back -- but not the reading it
    did: every object read is charged to a :class:`WorkBudget` that is never
    returned, so a set tried again for run after run stops being read once the
    pack has read twice its body budget. With *links* (every
    object's links, as ``walk`` reports them) the shallow-boundary list counts
    too: an attestation citing ten thousand events adds one object at depth 0
    but ten thousand boundaries.
    """
    sizes = Sizes(repo)
    budget = _BodyBudget(sizes, seen, max_body)
    work = WorkBudget(sizes, max_body)

    def charge(oid: str) -> None:  # both before the read: a refused object is never read
        budget.charge(oid)
        work.spend(oid)

    boundary = _Boundary(seen, links, limit)
    mark, reset = _source_hooks(repo)
    checked: set[str] = set()
    memo: dict[str, Any] = {}
    position = 0
    while position < len(runs):
        run = runs[position]
        position += 1
        if run in checked:
            continue
        checked.add(run)
        before = mark()
        related = _related(repo, run, limit, memo)
        reset(before)  # scanning for associations is not packing them
        subsets = []
        if related is not None:
            subsets = [related, [oid for oid in related if oid.startswith("annotation:")]]
        complete = False
        for index, subset in enumerate(subsets):
            fresh = [oid for oid in subset if oid not in seen]
            if len(seen) + len(fresh) > limit:
                continue
            before = mark()
            try:
                found_links: dict[str, tuple[str, ...]] = {}
                added, found = walk(repo, fresh, seen, depth, limit, charge, found_links)
                boundary.check(seen, added, found_links)
            except (KernelError, ValueError):
                budget.rollback()
                reset(before)
                continue
            budget.commit()
            boundary.commit()
            seen |= added
            runs.extend(found)
            complete = index == 0 or len(subset) == len(related or ())
            break
        if not complete and omitted is not None and run not in omitted:
            omitted.append(run)


class _BodyBudget:
    """The encoded pack body the graph used, and what associations may add."""

    def __init__(self, sizes: Sizes, seen: set[str], max_body: int | None):
        self.sizes = sizes
        self.limit = None if max_body is None else max_body - FRAMING_RESERVE
        self.used = sum(sizes(oid) for oid in seen) if self.limit else 0
        self.pending = 0

    def charge(self, oid: str) -> None:
        if self.limit is None:
            return
        size = self.sizes(oid)
        if self.used + self.pending + size > self.limit:
            raise OverBudget("pack exceeds maximum decompressed size")
        self.pending += size

    def commit(self) -> None:
        self.used += self.pending
        self.pending = 0

    def rollback(self) -> None:
        self.pending = 0


def _source_hooks(repo: Any) -> tuple[Callable[[], int], Callable[[int], None]]:
    mark = getattr(repo, "source_mark", None)
    reset = getattr(repo, "source_reset", None)
    if callable(mark) and callable(reset):
        return mark, reset
    return (lambda: 0), (lambda _mark: None)


class _Boundary:
    """The shallow-boundary set the pack will carry: links that leave it."""

    def __init__(self, seen: set[str], links: dict[str, tuple[str, ...]] | None, limit: int):
        self.links = links
        self.limit = limit
        self.current: set[str] = set()
        self.pending: set[str] | None = None
        if links is not None:
            self.current = {link for oid in seen for link in links.get(oid, ()) if link not in seen}

    def check(self, seen: set[str], added: set[str], found: dict[str, tuple[str, ...]]) -> None:
        if self.links is None:
            return
        grown = self.current - added
        for oid in added:
            grown.update(
                link for link in found.get(oid, ()) if link not in seen and link not in added
            )
        if len(grown) > self.limit:
            raise OverBudget("pack exceeds maximum shallow object count")
        self.pending = grown
        self.links.update(found)

    def commit(self) -> None:
        if self.pending is not None:
            self.current = self.pending
            self.pending = None
