"""Delete a local ref under the same lock and reflog discipline as ``commit_ref``.

The store had no local deletion: refs only ever moved. ``tine branch -d`` and
``tine tag -d`` need one, and it must not race a concurrent writer, so it takes
the ref's ``.lock`` exactly as ``commit_ref`` does, re-reads the value under
the lock, checks it against what the operator saw, removes the file and appends
a reflog row whose ``new`` is ``null`` -- the deletion stays recoverable with
``tine reflog`` + ``tine reset``.
"""

from __future__ import annotations

import os
from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.repository._paths import internal_path
from opentine.repository._ref_store import read_ref_oid
from opentine.repository._reflog import append_reflog, reflog_entry
from opentine.repository._refs import normalize_ref


def delete_ref(base: Path, name: str, expected_old: str, *, actor: str = "local") -> None:
    """Remove ref *name* if it still points at *expected_old*; refuse otherwise."""
    normalized = normalize_ref(name)
    ref_path = internal_path(Path(base), "refs", *Path(normalized).parts)
    lock_path = ref_path.with_name(ref_path.name + ".lock")
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError as exc:
        raise ValueError(f"ref {normalized!r} is locked by a concurrent write") from exc
    os.close(fd)
    try:
        old = read_ref_oid(Path(base), normalized)
        if old is None:
            raise KeyError(f"no such ref: {normalized}")
        if old != expected_old:
            raise ValueError(f"concurrent ref update: expected {expected_old!r}, found {old!r}")
        entry = reflog_entry(normalized, old, None, actor)
        ref_path.unlink()
        _fsync_dir(ref_path.parent)
        append_reflog(Path(base), normalized, entry)
    finally:
        lock_path.unlink(missing_ok=True)


__all__ = ["delete_ref"]
