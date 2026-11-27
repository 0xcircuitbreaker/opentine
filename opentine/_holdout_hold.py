"""Where holdout access records and canary registrations survive their files (0.60).

``DIR/access/NNNNNN.json`` and ``.tine/integrity/canaries/HEX.json`` are
ordinary files: a loop that can write them can delete an access record (and
lower a holdout's exposure) or overwrite a canary registration (and stop it
counting). So, as 0.57 does for loop stops and 0.59 for taints, each signed
record is also stored as a ``blob`` object with a ``tine hold`` row whose
target starts with ``holdout-access:ROOT:`` or ``holdout-canary:HEX:``. The
hold keeps the blob from every delete and ``tine hold release`` refuses it.
Readers take the union of the files and the held copies, so deleting a file
lowers nothing. An unreadable holds file raises (fail closed). Without a
repository there is nothing to hold, and only the files count.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine.repository._holds import (
    CANARY_HOLD,
    HOLDOUT_ACCESS,
    hold_row,
    holds_path,
    read_holds,
)


def access_target(root_hex: str, sequence: int) -> str:
    return f"{HOLDOUT_ACCESS}{root_hex}:{sequence:06d}"


def canary_target(hexdigest: str) -> str:
    return f"{CANARY_HOLD}{hexdigest}"


def _repo(root: Path | None) -> Any:
    from opentine.repo import Repo

    if root is None:
        return None
    try:
        return Repo.open(Path(root))
    except Exception:  # noqa: BLE001 - no repository: there are no holds to read
        return None


def keep(root: Path | None, target: str, data: bytes) -> str | None:
    """Store *data* as a blob and hold it under *target*; its object id (``None``: no repo)."""
    repo = _repo(root)
    if repo is None:
        return None
    oid = repo.put("blob", data, redact=False)
    hold_row(repo, oid, target)
    return oid


def kept(root: Path | None, prefix: str) -> list[tuple[str, bytes]]:
    """``(target, bytes)`` of every held copy whose target starts with *prefix*.

    Raises :class:`opentine.repository._holds.HoldError` when the holds file or
    a held blob cannot be read: a reader must not count fewer records then.
    """
    from opentine.repository._holds import HoldError

    repo = _repo(root)
    if repo is None:
        return []
    rows = [r for r in read_holds(holds_path(repo)) if r["target"].startswith(prefix)]
    out = []
    for row in sorted(rows, key=lambda r: (r["target"], r["oid"])):
        try:
            out.append((row["target"], bytes(repo.get(row["oid"]).body)))
        except Exception as exc:  # noqa: BLE001 - a held copy that cannot be read
            raise HoldError(f"held copy {row['oid']} ({row['target']}) cannot be read") from exc
    return out


__all__ = ["access_target", "canary_target", "keep", "kept"]
