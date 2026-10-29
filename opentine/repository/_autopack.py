"""Automatic packing of cold loose objects (0.13; no format change).

A recorded run leaves ~100 small loose files, and almost all of them are smaller
than a filesystem block: a 20-run repository measured 600 KB per run on disk
loose and ~90 KB once packed. :func:`maybe_autopack` runs ``gc`` for the caller
once enough *cold* loose objects have piled up.

Rules, each one a compatibility or safety guarantee:

* only a repository already at storage descriptor version 2 is packed; a
  version-1 repository is never upgraded behind the user's back (0.10 and older
  would then refuse it);
* only loose objects at least :data:`MIN_AGE` seconds old are packed, so a live
  writer's newest objects are left alone;
* the regular gc lock is taken without waiting: if any gc is running, this
  one is skipped; and it never raises into the caller (a recording must not
  fail because housekeeping did);
* ``OPENTINE_AUTO_PACK=0`` (or ``off``) disables it; a number sets the
  threshold. The repository's ``config.json`` may say the same with
  ``"auto_pack": false`` or ``"auto_pack": {"objects": N}`` (0.12 ignores it).
"""

from __future__ import annotations

import os
import time

from opentine.repository._config import STORAGE_VERSIONS, read_config
from opentine.repository._gc_tidy import old_loose
from opentine.repository._paths import internal_path

#: Cold loose objects that trigger a pack.
DEFAULT_THRESHOLD = 256
#: Loose objects younger than this (seconds) are never packed automatically.
MIN_AGE = 60.0
#: Small packs are merged once a repository holds more than this many.
MAX_PACKS = 8
#: The post-write hook rescans loose objects at most this often (seconds): an
#: object is never cold before MIN_AGE, so scanning more often finds nothing new.
RESCAN_INTERVAL = MIN_AGE / 4
_OFF = {"0", "off", "false", "no"}


def threshold(repo) -> int | None:
    """The configured trigger, or ``None`` when auto-pack is off for *repo*."""
    value = os.environ.get("OPENTINE_AUTO_PACK", "").strip().lower()
    if value in _OFF:
        return None
    if value.isdigit():
        return max(1, int(value))
    try:
        config = read_config(internal_path(repo.path, "config.json"))
    except (OSError, ValueError):
        return None
    if config.get("version") not in STORAGE_VERSIONS:
        return None
    setting = config.get("auto_pack", True)
    if setting is False:
        return None
    if isinstance(setting, dict):
        objects = setting.get("objects")
        if type(objects) is int and objects > 0:
            return objects
    return DEFAULT_THRESHOLD


def merge_candidates(sizes: dict[str, int]) -> list[str]:
    """The small packs to merge so pack sizes stay a geometric progression.

    Packs are taken smallest first while each next one is under twice the
    total taken so far; the large, settled packs are never rewritten.
    """
    if len(sizes) <= MAX_PACKS:
        return []
    ordered = sorted(sizes, key=lambda digest: (sizes[digest], digest))
    chosen = [ordered[0]]
    total = sizes[ordered[0]]
    for digest in ordered[1:]:
        if sizes[digest] >= 2 * total and len(ordered) - len(chosen) + 1 <= MAX_PACKS:
            break
        chosen.append(digest)
        total += sizes[digest]
    return chosen if len(chosen) > 1 else []


def _pack_sizes(root) -> dict[str, int]:
    sizes: dict[str, int] = {}
    directory = internal_path(root, "packs")
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return sizes
    for name in names:
        if name.endswith(".tpk") and len(name) == 68:
            try:
                sizes[name[:64]] = os.stat(directory / name).st_size
            except OSError:
                continue
    return sizes


def maybe_autopack(repo, *, min_age: float = MIN_AGE):
    """Pack cold loose objects if the threshold is reached; the ``GcResult`` or ``None``."""
    try:
        limit = threshold(repo)
        if limit is None or getattr(repo, "_storage_codec", None) is None:
            return None
        if len(old_loose(repo.path, min_age, limit=limit)) < limit:
            return None
        from opentine.repository._gc import gc

        merge = merge_candidates(_pack_sizes(repo.path))
        return gc(repo, min_age=min_age, merge_packs=merge, keep_transfer_packs=True)
    except Exception:  # noqa: BLE001 - housekeeping never fails a recording
        return None


def after_write(repo) -> None:
    """The shared post-write hook (``put_run``, ``fork``, annotate, recorder appends).

    Cheap below the threshold: :func:`maybe_autopack`'s scan of the loose
    objects runs once per ``Repo`` instance, then again only after about
    *threshold* more objects were stored through it (counted in
    ``store_envelope``) and at least :data:`RESCAN_INTERVAL` seconds later.
    Never raises.
    """
    state = repo.__dict__
    try:
        written = state.get("_autopack_writes", 0)
        last = state.get("_autopack_scan")
        if last is not None:
            limit = state.get("_autopack_limit") or DEFAULT_THRESHOLD
            if written < limit or time.monotonic() - last < RESCAN_INTERVAL:
                return
        state["_autopack_writes"] = 0
        state["_autopack_scan"] = time.monotonic()
        state["_autopack_limit"] = threshold(repo)
        if state["_autopack_limit"] is not None:
            maybe_autopack(repo)
    except Exception:  # noqa: BLE001 - housekeeping never fails a write
        return
