"""``tine serve reseal``: rewrite a tenant's objects in another at-rest form.

A 0.12 server stores new objects compressed then sealed (``TINEAES4``), which a
0.11 server cannot read. Before rolling a server back, an operator runs
``tine serve --root R --tenant T reseal --to aes3`` (with
``TINE_REMOTE_STORAGE_CODEC=off`` set for the server afterwards); ``--to aes4``
compresses objects written by older servers. Each object is read and verified
against its id before the new file atomically replaces the old one.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass

from opentine import _codec
from opentine._canon import _fsync_dir
from opentine.remote._object_file import read_object_file
from opentine.remote._sealed import SEALED4, seal_object


@dataclass(frozen=True)
class ResealResult:
    tenant: str
    rewritten: int
    unchanged: int


def reseal(objects, tenant: str, target: str, *, dry_run: bool = False) -> ResealResult:
    """Rewrite every object of *tenant* as ``aes3`` (uncompressed) or ``aes4``."""
    if target not in ("aes3", "aes4"):
        raise ValueError("--to must be aes3 or aes4")
    codec = None if target == "aes3" else (objects.codec or _codec.default_codec())
    rewritten = unchanged = 0
    for oid in objects.iter(tenant):
        path = objects._path(tenant, oid)
        compressed = read_object_file(path).startswith(SEALED4)  # no-follow, bounded
        if compressed == (codec is not None):
            unchanged += 1
            continue
        rewritten += 1
        if dry_run:
            continue
        raw = objects.get(tenant, oid)  # decrypts and checks the content id
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(seal_object(objects.keys, tenant, oid, raw, codec))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            _fsync_dir(path.parent)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    return ResealResult(tenant, rewritten, unchanged)
