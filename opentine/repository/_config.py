"""Small, bounded validation for the local v3 repository descriptor."""

from __future__ import annotations

import json
from pathlib import Path

MAX_CONFIG_BYTES = 64 * 1024


def validate_config(path: Path) -> None:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"not an OpenTine repository: {path.parent}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("repository config exceeds maximum size")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
        raise ValueError("repository config is malformed") from exc
    required = {
        "format": 3,
        "object_hash": "sha256",
        "repository": "opentine",
        "version": 1,
    }
    if not isinstance(value, dict) or any(
        value.get(key) != expected for key, expected in required.items()
    ):
        raise ValueError("repository config is incompatible")
