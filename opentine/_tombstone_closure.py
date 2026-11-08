"""What a verifier says of a run whose blob was purged: ``content-unavailable`` (0.46).

:func:`closure` walks a run's object graph through the objects it is given (a
pack, a bundle, a fetched closure). A linked object that is absent but named by
a tombstone is *content-unavailable*: the oid is still bound by every link, the
bytes are gone on purpose. An absent object with no tombstone is a failure
(``tombstone.missing-content``), exactly as before tombstones existed. The
tombstones' signatures are a separate question (:func:`opentine._tombstone.check`);
this walk needs only their shape. It is the reference for the
``tombstone.closure`` conformance op, ported to the pyz and the TS verifier.
"""

from __future__ import annotations

from typing import Any

from opentine._signed_record import RecordError
from opentine._tombstone import body
from opentine.kernel import ObjectEnvelope, validate_links

#: The most objects one walk visits (the pack object cap).
MAX_OBJECTS = 1_000_000


def closure(run: str, objects: dict[str, bytes], tombstones: list[Any]) -> dict[str, Any]:
    """``{run, objects, content_unavailable, state}``; :class:`RecordError` on a gap."""
    if not isinstance(tombstones, list):
        raise RecordError("tombstone.malformed", "tombstone is malformed: not a list")
    marked = {body(record)["oid"] for record in tombstones}
    seen: set[str] = set()
    unavailable: set[str] = set()
    stack = [run]
    while stack:
        oid = stack.pop()
        if oid in seen:
            continue
        seen.add(oid)
        if len(seen) > MAX_OBJECTS:
            raise RecordError("tombstone.missing-content", "the closure exceeds its object cap")
        if oid not in objects:
            if oid in marked:
                unavailable.add(oid)
                continue
            raise RecordError(
                "tombstone.missing-content",
                f"linked object {oid} is missing and no tombstone names it",
            )
        stack.extend(validate_links(ObjectEnvelope.decode(objects[oid], oid)))
    return {
        "run": run,
        "objects": len(seen) - len(unavailable),
        "content_unavailable": sorted(unavailable),
        "state": "content-unavailable" if unavailable else "verified",
    }


__all__ = ["closure"]
