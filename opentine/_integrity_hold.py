"""Where an integrity taint survives its file (0.59).

``.tine/integrity/taints/HEX.json`` is an ordinary file: a loop that can write
the repository can delete it and launder a score. So
:func:`opentine._integrity_run.taint` also stores the signed taint as an
``attestation`` object and adds a ``tine hold`` row
``{"oid": TAINT_ATTESTATION, "target": "integrity-taint:RUN"}``, as 0.57 does
for loop stops. The hold keeps the attestation from every delete, ``tine hold
release`` refuses it (a taint is never released), and ``promote`` and
``lineage check`` read it when the file is gone. An unreadable holds file
counts as a taint (fail closed); with no row (the holds file deleted or
edited) the stored taint attestation is read from the object store. Only a
run stored in the repository can be held this way (an attestation names a stored object).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine.repository._holds import (
    TAINT,
    HoldError,
    hold_row,
    holds_path,
    read_holds,
)


def target(run: str) -> str:
    return TAINT + run


def _repo(root: Path) -> Any:
    from opentine.repo import Repo

    try:
        return Repo.open(root)
    except Exception:  # noqa: BLE001 - no repository: there are no holds to read
        return None


def record(root: Path, document: dict[str, Any]) -> str | None:
    """Store *document* (a signed taint) and hold it; its object id.

    ``None`` when there is no repository or the run is not stored in it (an
    attestation must name a stored object): then only the file records it.
    """
    from opentine.kernel import KernelError

    repo = _repo(root)
    if repo is None:
        return None
    try:
        oid = repo.put("attestation", document)
    except KernelError:
        return None
    hold_row(repo, oid, target(document["claim"]["run"]))
    return oid


def held(root: Path, run: str) -> list[dict[str, Any]]:
    """The attestations held as taints on *run* (a placeholder row when holds are unreadable)."""
    repo = _repo(root)
    if repo is None:
        return []
    try:
        rows = [r for r in read_holds(holds_path(repo)) if r["target"] == target(run)]
    except HoldError as exc:
        return [{"unreadable": str(exc)}]
    oids = sorted(r["oid"] for r in rows)
    if not oids:  # the row is gone (holds file deleted or edited): the object still taints
        from opentine._integrity_run import TAINT
        from opentine.repository._stored_claims import stored

        oids = stored(repo, TAINT, lambda claim: claim.get("run") == run)
    out = []
    for oid in oids:
        try:
            out.append(repo.get(oid).payload())
        except Exception:  # noqa: BLE001 - a held taint that cannot be read still taints
            out.append({"unreadable": f"held taint {oid} cannot be read"})
    return out


__all__ = ["held", "record", "target"]
