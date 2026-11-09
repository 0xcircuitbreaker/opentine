"""Opting a repository in to per-kind zstd dictionary packs (0.50, ``_pack_dicts``).

A v3 pack whose blocks use a dictionary (codec 3) needs a 0.50 reader: older
ones refuse the codec byte. So the form is written only in a repository whose
descriptor says ``"pack_dicts": "zstd"`` and carries ``min_reader`` 0.50.0,
which every 0.26+ reader checks before it opens anything (as for blob deltas,
``_gc_deltas``). Opting in also moves the descriptor to object format 4.

Transfer never carries the form: wire packs, bundles and ``.tine`` exports are
built from canonical objects. ``disable`` rewrites every pack without
dictionaries first and lowers ``min_reader`` last, so no reader ever meets a
pack it cannot read.
"""

from __future__ import annotations

from pathlib import Path

from opentine.repository._config import (
    V4_MIN_READER,
    _to_v4,
    read_config,
    rewrite_config,
)
from opentine.repository._pack_dicts import forget_latest, tidy
from opentine.repository._paths import internal_path

MIN_READER = "0.50.0"
_KEY, _ON, _DRAINING = "pack_dicts", "zstd", "full"


def _version(text: object) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in str(text).split("."))
    except ValueError:
        return (0,)


def dicts_on(config: dict[str, object]) -> bool:
    """Whether packs written now may hold codec-3 (dictionary) blocks."""
    return config.get(_KEY) == _ON and _version(config.get("min_reader")) >= _version(MIN_READER)


def dicts_now(root: Path) -> bool:
    return dicts_on(read_config(internal_path(root, "config.json")))


def enable(repo) -> None:
    """Opt *repo* in (descriptor only; the caller's gc then rewrites the packs)."""

    def change(config: dict) -> bool:
        if dicts_on(config):
            return False
        _to_v4(config)
        config[_KEY] = _ON
        if _version(config.get("min_reader")) < _version(MIN_READER):
            config["min_reader"] = MIN_READER
        return True

    rewrite_config(repo.path, change)


def _floor(config: dict) -> str:
    """The ``min_reader`` the descriptor needs without dictionaries."""
    from opentine.repository._gc_deltas import MIN_READER as DELTAS
    from opentine.repository._gc_deltas import deltas_on
    from opentine.repository._packed_refs import MIN_READER as REFS
    from opentine.repository._packed_refs import refs_packed

    if deltas_on(config):
        return DELTAS
    return REFS if refs_packed(config) else V4_MIN_READER


def disable(repo) -> None:
    """Rewrite every pack without dictionaries, then let 0.40-0.49 readers open it."""
    from opentine.repository._gc import gc

    def drain(config: dict) -> bool:
        if config.get(_KEY) != _ON:
            return False
        config[_KEY] = _DRAINING  # from here on no writer uses a dictionary
        return True

    def drop(config: dict) -> bool:
        if _KEY not in config:
            return False
        del config[_KEY]
        if config.get("min_reader") == MIN_READER:
            config["min_reader"] = _floor(config)
        return True

    rewrite_config(repo.path, drain)
    if read_config(internal_path(repo.path, "config.json")).get(_KEY) is None:
        return
    gc(repo, repack=True, keep_transfer_packs=True)
    forget_latest(repo.path)
    tidy(repo.path)
    rewrite_config(repo.path, drop)
