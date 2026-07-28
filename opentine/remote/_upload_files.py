"""Exclusive, durable creation of resumable-upload state files."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from opentine._canon import _fsync_dir


def create_upload_files(
    part: Path, metadata_path: Path, metadata: dict[str, Any]
) -> tuple[Path, Path]:
    part_fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(part_fd)
    part.chmod(0o600)
    try:
        stored = {**metadata, "offset": 0, "spool_size": 0}
        metadata_fd = os.open(metadata_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(metadata_fd, "w", encoding="utf-8") as handle:
            json.dump(stored, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        metadata_path.chmod(0o600)
        _fsync_dir(metadata_path.parent)
    except Exception:
        part.unlink(missing_ok=True)
        metadata_path.unlink(missing_ok=True)
        raise
    return part, metadata_path
