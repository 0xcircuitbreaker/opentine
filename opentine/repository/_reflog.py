"""Append-only ref history (reflog) writes for the v3 store."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.kernel import canonical_json
from opentine.repository._paths import durable_directory, internal_path

#: Per-ref reflog bound. A reflog is history, never authority (SPEC §2.6), and
#: grew without limit under ref churn (``experiments/*`` over MCP): once an
#: append would pass this, the oldest rows go and the newest half is kept.
MAX_REFLOG_BYTES = 1024 * 1024


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
    """Append *entry* under the ref's lock, dropping the oldest rows past the bound."""
    log_path = internal_path(base, "logs", *Path(normalized).parts)
    durable_directory(log_path.parent)
    try:
        size = log_path.stat().st_size
    except FileNotFoundError:
        size = 0
    if size + len(entry) > MAX_REFLOG_BYTES:
        _rotate(log_path, size, entry)
    else:
        with log_path.open("ab") as handle:
            handle.write(entry)
            handle.flush()
            os.fsync(handle.fileno())
    _fsync_dir(log_path.parent)


def _rotate(log_path: Path, size: int, entry: bytes) -> None:
    """Replace the log, atomically, with its newest whole rows plus *entry*."""
    keep = MAX_REFLOG_BYTES // 2
    with log_path.open("rb") as handle:
        handle.seek(max(0, size - keep))
        tail = handle.read(keep)
    if size > keep:  # the read began mid-row: drop the partial first row
        tail = tail[tail.find(b"\n") + 1 :] if b"\n" in tail else b""
    fd, temporary = tempfile.mkstemp(dir=log_path.parent, prefix=f".{log_path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(tail + entry)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, log_path)
    finally:
        Path(temporary).unlink(missing_ok=True)
