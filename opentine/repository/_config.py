"""Small, bounded validation for the local v3 repository descriptor."""

from __future__ import annotations

import json
from pathlib import Path

from opentine.kernel import canonical_json, validate_json_shape

MAX_CONFIG_BYTES = 64 * 1024

#: Descriptor version 2 marks a repository whose objects may be stored
#: compressed or packed (0.11+). Earlier readers require version 1 and so refuse
#: it cleanly, instead of failing on the first compressed object they meet.
STORAGE_VERSION = 2
#: Descriptor version 3 (0.13+, opt-in with ``tine gc --upgrade``) marks a
#: repository that may hold storage-v3 packs (``_pack_v3``). opentine 0.12 and
#: older accept only 1 and 2, so they refuse it at open with "repository config
#: is incompatible"; ``tine gc --downgrade`` returns it to version 2.
STORAGE_V3 = 3
STORAGE_VERSIONS = (STORAGE_VERSION, STORAGE_V3)
_FIXED = {"format": 3, "object_hash": "sha256", "repository": "opentine"}
_VERSIONS = (1, STORAGE_VERSION, STORAGE_V3)
#: Written into a v3 descriptor for whoever opens it by hand (readers ignore it).
V3_NOTE = "storage version 3 needs opentine 0.13 or newer; `tine gc --downgrade` returns it to 2"
_CODECS = frozenset({"zlib", "zstd", "none"})


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def read_config(path: Path) -> dict[str, object]:
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
        for key, expected in _FIXED.items()
    ):
        raise ValueError("repository config is incompatible")
    version = value.get("version")
    if type(version) is int and version > _VERSIONS[-1]:
        raise ValueError(
            f"repository config is incompatible: storage version {version} is newer than "
            f"this opentine supports ({_VERSIONS[-1]}); upgrade opentine to open it"
        )
    if isinstance(version, bool) or version not in _VERSIONS:
        raise ValueError("repository config is incompatible")
    storage_codec(value)
    return value


def validate_config(path: Path) -> None:
    read_config(path)


def storage_codec(config: dict[str, object]) -> str | None:
    """The configured object codec, or ``None`` for a plain (version 1) store."""
    if config.get("version") not in STORAGE_VERSIONS:
        return None
    storage = config.get("storage")
    codec = storage.get("compression") if isinstance(storage, dict) else None
    if codec not in _CODECS:
        raise ValueError("repository storage codec is not supported by this opentine")
    return str(codec)


def config_bytes(codec: str | None) -> bytes:
    """The descriptor ``Repo.init`` writes: version 1 plain, version 2 with storage."""
    value: dict[str, object] = {**_FIXED, "version": 1}
    if codec is not None:
        value.update(version=STORAGE_VERSION, storage={"compression": codec})
    return canonical_json(value) + b"\n"


def storage_version(config: dict[str, object]) -> int:
    version = config.get("version")
    return version if type(version) is int else 1
