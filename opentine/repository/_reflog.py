"""Append-only ref history (reflog) writes for the v3 store."""

from __future__ import annotations

import os
import time
from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.kernel import canonical_json
from opentine.repository._paths import durable_directory, internal_path


def reflog_entry(normalized: str, old: str | None, new_oid: str, actor: str) -> bytes:
    """Serialize and validate a reflog row before its corresponding ref commits."""
    if not isinstance(actor, str):
        raise TypeError("reflog actor must be a string")
    if len(actor) > 4096:
        raise ValueError("reflog actor exceeds its size limit")
    return (
        canonical_json(
            {
                "actor": actor,
                "new": new_oid,
                "old": old,
                "ref": normalized,
                # String-encoded because canonical JSON rejects integers beyond 2**53-1.
                "time_ns": str(time.time_ns()),
            }
        )
        + b"\n"
    )


def append_reflog(base: Path, normalized: str, entry: bytes) -> None:
    log_path = internal_path(base, "logs", *Path(normalized).parts)
    durable_directory(log_path.parent)
    with log_path.open("ab") as handle:
        handle.write(entry)
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_dir(log_path.parent)
