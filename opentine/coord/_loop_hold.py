"""Where a loop stop survives its coord record (0.57).

``coord/loops/LOOP`` is an ordinary ref: anything that can write refs can
delete or rewrite it. So :func:`opentine.coord._loop_stop.stop` also adds a
``tine hold`` row ``{"oid": STOP_ATTESTATION, "target": "loop-stop:LOOP"}``.
The hold keeps the attestation from every delete, ``tine hold release``
refuses it (there is no un-stop), and the fence and ``promote`` read it when
the ref has no stop. An unreadable holds file counts as a stop (fail closed),
and with the holds file deleted the stored stop attestations are read.

A task id is also in the namespace of each loop its dotted prefixes name
(``opt.gen-3`` is in ``opt``), so a generation added without ``--loop`` is
fenced all the same.
"""

from __future__ import annotations

from typing import Any

from opentine.repository._holds import (
    LOOP_STOP,
    HoldError,
    hold_row,
    holds_path,
    read_holds,
)


def target(loop: str) -> str:
    return LOOP_STOP + loop


def record(repo: Any, loop: str, oid: str) -> None:
    hold_row(repo, oid, target(loop))


def held_stop(repo: Any, loop: str) -> dict[str, Any] | None:
    """The stop value a hold keeps for *loop* (``None`` when none does)."""
    try:
        rows = [r for r in read_holds(holds_path(repo)) if r["target"] == target(loop)]
    except HoldError as exc:
        return {"loop": loop, "status": "stopped", "stop": None, "signer": None,
                "source": "hold", "detail": str(exc)}  # fmt: skip
    if not rows and not holds_path(repo).exists():  # the file was deleted: read the objects
        from opentine.coord._loop_stop import CONVENTION
        from opentine.repository._stored_claims import stored

        rows = [{"oid": o} for o in stored(repo, CONVENTION, lambda c: c.get("loop") == loop)]
    if not rows:
        return None
    oid = sorted(r["oid"] for r in rows)[0]
    try:
        signer = repo.get(oid).payload().get("signer")
    except Exception:  # noqa: BLE001 - reported unverified by verify_stop; still a stop
        signer = None
    return {"loop": loop, "status": "stopped", "stop": oid, "signer": signer, "source": "hold"}


def namespace(task: str) -> list[str]:
    """The loops whose namespace holds *task*: each proper dotted prefix."""
    parts = task.split(".")
    return [".".join(parts[:n]) for n in range(1, len(parts))]


__all__ = ["held_stop", "namespace", "record", "target"]
