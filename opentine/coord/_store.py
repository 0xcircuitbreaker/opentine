"""Read and compare-and-swap one ``coord/*`` record (an annotation chain).

A record is the annotation ``{"coord": "opentine-coord/1", "kind": KIND,
"value": {...}, "previous_id": PRIOR}`` (``previous_id`` omitted for the first
version). :func:`swap` writes the next version and moves the ref only if it
still names *expected_old*; a writer that lost the race gets ``None`` back and
nothing changed. Local repositories use the ref machinery's own CAS
(:meth:`Repo.update_ref`, under the ref guard lock and reflog).
"""

from __future__ import annotations

from typing import Any

from opentine.coord import FORMAT
from opentine.repository._ref_retry import RefCasMismatch


def read(repo: Any, name: str, kind: str) -> tuple[str | None, dict[str, Any] | None]:
    """``(oid, value)`` of the record *name* names, or ``(None, None)``."""
    oid = repo.read_ref(name)
    if oid is None:
        return None, None
    payload = repo.get(oid).payload()
    if (
        not isinstance(payload, dict)
        or payload.get("coord") != FORMAT
        or payload.get("kind") != kind
        or not isinstance(payload.get("value"), dict)
    ):
        raise ValueError(f"{name} is not an {FORMAT} {kind} record")
    return oid, payload["value"]


def swap(
    repo: Any, name: str, kind: str, value: dict[str, Any], expected_old: str | None
) -> str | None:
    """Write *value* as the next version; its oid, or ``None`` if the ref moved."""
    payload: dict[str, Any] = {"coord": FORMAT, "kind": kind, "value": value}
    if expected_old:
        payload["previous_id"] = expected_old
    oid = repo.put("annotation", payload)
    try:
        repo.update_ref(name, oid, expected_old=expected_old, actor="coord")
    except RefCasMismatch:
        return None
    return oid


def history(repo: Any, oid: str | None, limit: int = 1000) -> list[dict[str, Any]]:
    """Every version's value, newest first (at most *limit*)."""
    rows: list[dict[str, Any]] = []
    while oid and len(rows) < limit:
        payload = repo.get(oid).payload()
        rows.append(payload["value"])
        oid = payload.get("previous_id")
    return rows


__all__ = ["history", "read", "swap"]
