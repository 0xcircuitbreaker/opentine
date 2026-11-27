"""Stored attestations by claim convention: what survives a deleted holds file.

Hold rows live in ``.tine/holds``, an ordinary file. A never-released hold (an
integrity taint, a loop stop) also keeps its record as an ``attestation``
object, so a reader that finds no row falls back to the object store, the way
:mod:`opentine._organism_registry` reads stored tags: deleting or editing the
holds file never clears the record.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def stored(repo: Any, convention: str, match: Callable[[dict[str, Any]], bool]) -> list[str]:
    """Sorted ids of stored attestations whose claim follows *convention* and *match*."""
    out = []
    for oid in repo.iter_oids():
        if not oid.startswith("attestation:"):
            continue
        try:
            payload = repo.get(oid).payload()
        except Exception:  # noqa: BLE001 - an unreadable object is no record
            continue
        claim = payload.get("claim") if isinstance(payload, dict) else None
        if isinstance(claim, dict) and claim.get("convention") == convention and match(claim):
            out.append(oid)
    return sorted(out)


__all__ = ["stored"]
