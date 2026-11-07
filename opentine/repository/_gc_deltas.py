"""Opting a repository in to ``BLOB_DELTA`` local packs (0.40, ``_blob_delta``).

A v3 pack that stores a blob as a delta needs a 0.40 reader: older ones refuse
the index entry. So the form is written only in a repository whose descriptor
says ``"packs": "delta"`` and carries ``min_reader`` 0.40.0, which every 0.26+
reader checks before it opens anything (0.37 did the same for packed-refs).
Opting in also moves the descriptor to object format 4, which 0.9-0.25 refuse.

Transfer never carries the form: wire packs, bundles and ``.tine`` exports are
built from canonical objects, so a clone or fetch by an older release reads
them as before. ``disable`` rewrites every pack without deltas first and lowers
``min_reader`` last, so no reader ever meets a pack it cannot read.
"""

from __future__ import annotations

from opentine.repository._config import (
    V4_MIN_READER,
    _to_v4,
    read_config,
    rewrite_config,
)
from opentine.repository._packed_refs import MIN_READER as REFS_MIN_READER
from opentine.repository._packed_refs import refs_packed
from opentine.repository._paths import internal_path

MIN_READER = "0.40.0"
_KEY, _ON, _DRAINING = "packs", "delta", "full"


def _version(text: object) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in str(text).split("."))
    except ValueError:
        return (0,)


def deltas_on(config: dict[str, object]) -> bool:
    """Whether packs written now may hold ``BLOB_DELTA`` objects."""
    return config.get(_KEY) == _ON and _version(config.get("min_reader")) >= _version(MIN_READER)


def blob_deltas_now(root) -> bool:
    """Whether a v3 pack written into *root* now stores blob deltas (gc and autopack)."""
    return deltas_on(read_config(internal_path(root, "config.json")))


def enable(repo) -> None:
    """Opt *repo* in (descriptor only; the caller's gc then rewrites the packs)."""

    def change(config: dict) -> bool:
        if deltas_on(config):
            return False
        _to_v4(config)
        config[_KEY] = _ON
        if _version(config.get("min_reader")) < _version(MIN_READER):
            config["min_reader"] = MIN_READER
        return True

    rewrite_config(repo.path, change)


def disable(repo) -> None:
    """Rewrite every pack without deltas, then let 0.26-0.39 readers open it again."""
    from opentine.repository._gc import gc

    def drain(config: dict) -> bool:
        if config.get(_KEY) != _ON:
            return False
        config[_KEY] = _DRAINING  # from here on no writer stores a delta
        return True

    def drop(config: dict) -> bool:
        if _KEY not in config:
            return False
        del config[_KEY]
        if config.get("min_reader") == MIN_READER:
            config["min_reader"] = REFS_MIN_READER if refs_packed(config) else V4_MIN_READER
        return True

    rewrite_config(repo.path, drain)
    if read_config(internal_path(repo.path, "config.json")).get(_KEY) is None:
        return
    gc(repo, repack=True, keep_transfer_packs=True)
    rewrite_config(repo.path, drop)
