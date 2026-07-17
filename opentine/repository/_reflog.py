"""Append-only ref history (reflog) writes for the v3 store."""

from __future__ import annotations

import os
import time
from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.kernel import canonical_json
from opentine.repository._paths import internal_path


def append_reflog(base: Path, normalized: str, old: str | None, new_oid: str, actor: str) -> None:
    log_path = internal_path(base, "logs", *Path(normalized).parts)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = canonical_json(
        {
            "actor": actor,
            "new": new_oid,
            "old": old,
            "ref": normalized,
            # String-encoded so full nanosecond precision survives canonical JSON,
            # which rejects integers beyond the exactly representable range (2**53-1).
            "time_ns": str(time.time_ns()),
        }
    )
    with log_path.open("ab") as handle:
        handle.write(entry + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_dir(log_path.parent)
