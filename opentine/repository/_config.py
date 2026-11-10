"""Small, bounded validation for the local v3 repository descriptor."""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
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
#: Object format 4 (SPEC §2.2, 9.10). A v4 descriptor spells the object format
#: ``"objects": 4`` *instead of* ``"format": 3``: every 0.9-0.25 reader requires
#: ``format == 3`` and so refuses it at open, while ``version`` keeps meaning the
#: storage layout (1, 2 or 3) and ``tine gc --upgrade/--downgrade`` cannot clear it.
OBJECTS_V4 = 4
V4_MIN_READER = "0.26.0"
#: The newest ``min_reader`` this build honours (the format it implements; it
#: moves with the format, not with the package version).
READER_VERSION = (0, 50, 0)  # 0.37: packed refs; 0.40: blob deltas; 0.50: pack dicts
_FIXED_V4 = {"object_hash": "sha256", "objects": OBJECTS_V4, "repository": "opentine"}
_SEMVER = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,5})")
_REFUSED = "repository config is incompatible"


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
    fixed = _object_format(value) if isinstance(value, dict) else _FIXED
    if not isinstance(value, dict) or any(
        isinstance(value.get(key), bool) or value.get(key) != expected
        for key, expected in fixed.items()
    ):
        raise ValueError(_REFUSED)
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


def _object_format(value: dict[str, object]) -> dict[str, object]:
    """Enforce ``min_reader`` and pick the required pairs: v3 or object format 4."""
    if "min_reader" in value:
        text = value["min_reader"]
        match = _SEMVER.fullmatch(text) if isinstance(text, str) else None
        if match is None:
            raise ValueError(f"{_REFUSED}: min_reader is not a MAJOR.MINOR.PATCH version")
        if tuple(int(part) for part in match.groups()) > READER_VERSION:
            supported = ".".join(map(str, READER_VERSION))
            raise ValueError(
                f"{_REFUSED}: this repository needs opentine {text} or newer to read it "
                f"(this build reads repositories up to {supported}); upgrade opentine"
            )
    if "objects" not in value:
        return _FIXED
    objects = value["objects"]
    if type(objects) is int and objects > OBJECTS_V4:
        raise ValueError(
            f"{_REFUSED}: object format {objects} is newer than this opentine supports "
            f"({OBJECTS_V4}); upgrade opentine to open it"
        )
    if "format" in value or "min_reader" not in value:  # one object-format key, gated
        raise ValueError(_REFUSED)
    return _FIXED_V4


def is_v4_config(config: dict[str, object]) -> bool:
    return config.get("objects") == OBJECTS_V4 and type(config.get("objects")) is int


def v4_config(config: dict[str, object]) -> dict[str, object]:
    """*config* as an object-format-4 descriptor, every other key kept."""
    value = {key: item for key, item in config.items() if key != "format"}
    value.update(objects=OBJECTS_V4, min_reader=V4_MIN_READER)
    return value


@contextmanager
def config_lock(root: Path, timeout: float = 30.0) -> Iterator[None]:
    """Serialize every descriptor read-modify-write (``mark_v4``, gc's version
    changes): without it a gc that read the descriptor before ``mark_v4`` wrote
    it would write the old object format back. Short-held, so contenders wait;
    a lock left by a dead process is broken (``_lockfile.acquire``).
    """
    from opentine.repository import _winretry
    from opentine.repository._lockfile import acquire
    from opentine.repository._paths import internal_path

    path = internal_path(root, "config.lock")
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.close(acquire(path, 0o600))
            break
        except FileExistsError:
            if time.monotonic() > deadline:
                raise ValueError(f"repository config is locked ({path}); remove it if stale")
            time.sleep(0.01)
    try:
        yield
    finally:
        _winretry.unlink(path)


def rewrite_config(root: Path, change: Callable[[dict[str, object]], bool]) -> dict[str, object]:
    """Re-read the descriptor under :func:`config_lock`, let *change* edit it in
    place (returning whether it did), and write it back atomically if so."""
    from opentine.repository._paths import atomic_bytes, internal_path

    path = internal_path(root, "config.json")
    with config_lock(root):
        config = read_config(path)
        if change(config):
            atomic_bytes(path, canonical_json(config) + b"\n")
    return config


def _to_v4(config: dict[str, object]) -> bool:
    if is_v4_config(config):
        return False
    upgraded = v4_config(config)
    config.clear()
    config.update(upgraded)
    return True


def mark_v4(repo) -> None:
    """Make *repo*'s descriptor object format 4, before its first v4 object.

    Descriptor first, object after (the order ``tine gc --upgrade`` uses): a
    crash in between leaves a v4 descriptor over v3-only objects, which every
    reader that may open it reads; never a v4 object an old writer could extend.
    The rewrite holds :func:`config_lock`, so a concurrent gc cannot undo it.
    """
    if repo.__dict__.get("_v4_marked"):
        return
    from opentine.repository._paths import internal_path

    if not is_v4_config(read_config(internal_path(repo.path, "config.json"))):
        rewrite_config(repo.path, _to_v4)
    repo.__dict__["_v4_marked"] = True


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


def config_bytes(codec: str | None, *, v4: bool = False) -> bytes:
    """The descriptor ``Repo.init`` writes: version 1 plain, version 2 with storage;
    object format 4 (the 0.26 default) when *v4*."""
    value: dict[str, object] = {**_FIXED, "version": 1}
    if codec is not None:
        value.update(version=STORAGE_VERSION, storage={"compression": codec})
    return canonical_json(v4_config(value) if v4 else value) + b"\n"


def storage_version(config: dict[str, object]) -> int:
    version = config.get("version")
    return version if type(version) is int else 1
