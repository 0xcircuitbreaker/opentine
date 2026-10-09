"""Small, bounded validation for the local v3 repository descriptor."""

from __future__ import annotations

import json
from pathlib import Path

from opentine.kernel import validate_json_shape

MAX_CONFIG_BYTES = 64 * 1024


_REQUIRED = {"format": 3, "object_hash": "sha256", "repository": "opentine", "version": 1}


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def validate_config(path: Path) -> None:
    """Accept the descriptor ``Repo.init`` writes, read as SPEC §2.2 says.

    Unknown keys and any formatting stay accepted (the published conformance
    vectors require it). Two readings that could disagree are refused: a key
    given twice (which value wins is parser-specific), and ``true`` for ``1``,
    which Python's ``==`` let through. Strict UTF-8 (a BOM is tolerated).
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"not an OpenTine repository: {path.parent}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("repository config exceeds maximum size")
    try:
        validate_json_shape(raw, max_tokens=10_000)
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique)
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise ValueError("repository config is malformed") from exc
    if not isinstance(value, dict) or any(
        isinstance(value.get(key), bool) or value.get(key) != expected
        for key, expected in _REQUIRED.items()
    ):
        raise ValueError("repository config is incompatible")
