"""A pack that associations cannot make fail, whatever the receiver already holds.

Associations are budgeted against the full reachable set, but the pack that is
built leaves out what the receiver listed as *haves* (and, on a typed fetch,
whatever ``select`` drops). Every link into an object left out that way joins the
pack's shallow list, so a writer's attestation citing objects the reader already
held could still push an incremental depth-limited fetch past the shallow cap.
When a pack with associations cannot be built, it is rebuilt from the object
graph alone and every run in it is reported as *omitted*: the transfer succeeds
without the associations instead of failing. A graph that does not fit by itself
still raises, as before.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from opentine.kernel import KernelError, validate_links
from opentine.repository._semantic_view import semantic_view
from opentine.repository.pack import (
    MAX_PACK_BODY_BYTES,
    create_pack,
    negotiate,
    reachable,
)

Select = Callable[[Any, list[str]], list[str]]


def fitted_pack(
    repo: Any,
    wants: list[str],
    haves: list[str],
    *,
    depth: int | None = None,
    omitted: list[str] | None = None,
    select: Select | None = None,
) -> tuple[bytes, list[str]]:
    """The pack for *wants* minus *haves*, and the object ids it carries."""
    view = semantic_view(repo, max_source_bytes=MAX_PACK_BODY_BYTES)
    mark = view.source_mark()
    short: list[str] = []
    missing = negotiate(view, wants, haves, depth=depth, omitted=short)
    if select is not None:
        missing = select(view, missing)
    try:
        data = create_pack(view, missing)
    except KernelError:
        view.source_reset(mark)
        plain = set(reachable(view, wants, depth=depth, include_associated=False))
        missing = sorted(plain - set(haves))
        if select is not None:
            missing = select(view, missing)
        data = create_pack(view, missing)  # the graph alone does not fit: raise
        short = sorted(oid for oid in plain if oid.startswith("run:"))
    if omitted is not None:
        omitted.extend(run for run in short if run not in omitted)
    return data, missing


def typed_selection(object_types: set[str]) -> Select:
    """Keep objects of *object_types*, plus the missing objects they link to."""

    def select(repo: Any, missing: list[str]) -> list[str]:
        held = set(missing)
        chosen = {oid for oid in missing if oid.split(":", 1)[0] in object_types}
        chosen.update(
            link for oid in tuple(chosen) for link in validate_links(repo.get(oid)) if link in held
        )
        return sorted(chosen)

    return select


__all__ = ["fitted_pack", "typed_selection"]
