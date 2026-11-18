"""Auto-pack writes the current local pack format (0.58; no format change).

Before 0.58 a repository at storage descriptor version 2 (what ``Repo.init``
writes) was auto-packed in the version-1 local pack format (``TINELP1``), which
only the Python reader opens. Auto-pack now first moves such a repository to
storage version 3, so every pack it writes is ``TINELP3``: read by this tree, by
the TypeScript verifier (``localpack.ts``, conformance family ``29-localpack``)
and by every release since 0.13, the 0.34 peer-compat reader included.
``tine-verify.pyz`` reads no repository directory. Packs already on disk are not
rewritten here; they keep reading, and merging them later writes format 3.

Rules:

* only a version-2 repository moves (a version-1 one is never auto-packed);
* the move is made under the gc lock, re-checked there, and skipped (never
  waited for) while any gc runs;
* ``tine gc --downgrade`` pins ``"auto_pack": {"format": 1}`` in ``config.json``
  so an explicit downgrade is never undone; that pin, or
  ``OPENTINE_AUTO_PACK_FORMAT=1``, keeps auto-pack on the version-1 format.
"""

from __future__ import annotations

import os
from typing import Any

from opentine import _codec
from opentine.kernel import KernelError
from opentine.repository._config import STORAGE_VERSION, read_config, storage_version
from opentine.repository._paths import internal_path

ENV = "OPENTINE_AUTO_PACK_FORMAT"


def pinned(setting: Any) -> Any:
    """``config.json``'s ``auto_pack`` value with the version-1 format pinned."""
    if setting is False:
        return False
    return {**(setting if isinstance(setting, dict) else {}), "format": 1}


def _wants_move(config: dict) -> bool:
    setting = config.get("auto_pack")
    if isinstance(setting, dict) and setting.get("format") == 1:
        return False
    return storage_version(config) == STORAGE_VERSION


def adopt_current_format(repo) -> bool:
    """Move a version-2 repository to storage version 3; whether it moved."""
    from opentine.repository._gc import STORAGE_V3, gc_lock, set_storage_version

    if os.environ.get(ENV, "").strip() == "1":
        return False
    codec = getattr(repo, "_storage_codec", None)
    if codec in (None, "none") or not _codec.available(codec):
        return False
    path = internal_path(repo.path, "config.json")
    if not _wants_move(read_config(path)):
        return False
    try:
        with gc_lock(repo.path):
            if not _wants_move(read_config(path)):  # a downgrade may have just run
                return False
            set_storage_version(repo, STORAGE_V3, codec)
    except KernelError:  # another gc holds the lock: try again next time
        return False
    return True


__all__ = ["ENV", "adopt_current_format", "pinned"]
