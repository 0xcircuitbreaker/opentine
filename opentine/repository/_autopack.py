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
  writer's newest objects are left alone -- except the recorder's own (0.14.1):
  a burst of appends writes a full run snapshot per event, so it packs the
  objects *this* ``Repo`` stored once :data:`DEFAULT_THRESHOLD` of them are
  loose, whatever their age. Packing never deletes an object: like ``tine gc``
  it writes and reads back the pack before a loose copy is removed, and the new
  pack's mtime keeps every object in it young for ``tine prune``;
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


def maybe_autopack(repo, *, min_age: float = MIN_AGE, own: frozenset[str] = frozenset()):
    """Pack cold loose objects if the threshold is reached; the ``GcResult`` or ``None``.

    Loose oids in *own* (stored by this process) count and pack whatever their age.
    """
    try:
        limit = threshold(repo)
        if limit is None or getattr(repo, "_storage_codec", None) is None:
            return None
        if len(old_loose(repo.path, min_age, limit=limit, own=own)) < limit:
            return None
        from opentine.repository._gc import gc

        merge = merge_candidates(_pack_sizes(repo.path))
        return gc(repo, min_age=min_age, merge_packs=merge, keep_transfer_packs=True, own=own)
    except Exception:  # noqa: BLE001 - housekeeping never fails a recording
        return None


def after_write(repo, *, own: bool = False) -> None:
    """The shared post-write hook (``put_run``, ``fork``, annotate, recorder appends).

    Cheap below the threshold: :func:`maybe_autopack`'s scan of the loose
    objects runs once per ``Repo`` instance, then again only after about
    *threshold* more objects were stored through it (counted in
    ``store_envelope``) and at least :data:`RESCAN_INTERVAL` seconds later.
    With *own* (recorder appends), once *threshold* objects stored through this
    ``Repo`` are pending, they are packed at once whatever their age.
    Never raises.
    """
    state = repo.__dict__
    try:
        mine = state.setdefault("_autopack_own", set())
        if not own:
            mine.clear()  # only a recorder's burst packs hot objects
        elif len(mine) >= (state.get("_autopack_limit") or DEFAULT_THRESHOLD):
            state["_autopack_limit"] = threshold(repo)
            if state["_autopack_limit"] is not None:
                before = set(_pack_sizes(repo.path))
                if maybe_autopack(repo, own=frozenset(mine)) is not None:
                    hot = state.setdefault("_autopack_hot", set())
                    hot.update(set(_pack_sizes(repo.path)) - before)
            mine.clear()  # packed, or left to the cold-object path (gc busy)
            return
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


def settle(repo) -> None:
    """End of a recording: fold the packs its burst wrote into one, with its rest.

    Without a burst this is :func:`maybe_autopack` (cold objects only). After
    one, the session's own small packs and its remaining own loose objects are
    packed together, so a finished session leaves one pack, not several. Packs
    written by anything else are left alone. Never raises.
    """
    state = repo.__dict__
    hot = state.pop("_autopack_hot", set()) & set(_pack_sizes(repo.path))
    mine = frozenset(state.get("_autopack_own", ()))
    try:
        if not hot or threshold(repo) is None:
            maybe_autopack(repo)
            return
        from opentine.repository._gc import gc

        gc(repo, min_age=MIN_AGE, merge_packs=sorted(hot), keep_transfer_packs=True, own=mine)
        state["_autopack_own"] = set()
    except Exception:  # noqa: BLE001 - housekeeping never fails a recording
        return
