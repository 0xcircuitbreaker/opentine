"""One pack per run (0.40, P2): batch a run's new objects into a single pack.

A run written loose costs two fsyncs per object (the file and its directory),
which capped recording near 57 events/s. Inside :func:`batched` every
:func:`~opentine.repository._storage.write_object` *stages* its canonical bytes
in memory instead; :func:`flush` writes them as one local pack (the format the
repository's gc writes, so every reader since packs exist understands it) with
one fsync per pack file and one directory sync, then the caller updates refs.

Crash safety is the pack's own: the ``.tpk`` and ``.tidx`` are made durable
under temporary names before either is renamed in, and the index rename
publishes the pack. A crash before the ref update leaves an unreferenced pack
(``tine gc``/``prune`` reclaims it, fsck reads it clean); a ref never names an
object that is not durable, because refs move only after :func:`flush`.

Reads and existence checks inside a batch see the staged objects, so link
validation behaves exactly as with loose writes. A repository whose descriptor
is version 1 (no packs) and a batch of a single object use the loose path.
"""

from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from opentine import _codec
from opentine._canon import _fsync_dir, full_fsync
from opentine.repository import _winretry
from opentine.repository._config import STORAGE_VERSIONS, read_config, storage_version
from opentine.repository._pack_index import MAX_PACK_OBJECTS
from opentine.repository._paths import durable_directory, internal_path

_KEY = "_write_batch"
_OFF = {"0", "off", "false", "no"}


def staged(repo) -> dict[str, bytes] | None:
    """The active batch of *repo* (oid -> canonical bytes), or ``None``."""
    return getattr(repo, "__dict__", {}).get(_KEY)


def _pack_version(repo) -> int | None:
    """1 or 3, or ``None`` to write loose (version-1 store, or opted out).

    ``OPENTINE_RUN_PACK=0`` or ``"run_pack": false`` in ``config.json`` keeps
    the pre-0.40 one-file-per-object writes.
    """
    if os.environ.get("OPENTINE_RUN_PACK", "").strip().lower() in _OFF:
        return None
    try:
        config = read_config(internal_path(repo.path, "config.json"))
    except (OSError, ValueError):
        return None
    version = storage_version(config)
    if config.get("run_pack", True) is False:
        return None
    if version not in STORAGE_VERSIONS:
        return None  # a version-1 store has no packs; never upgrade it silently
    return 3 if version == 3 else 1


@contextmanager
def batched(repo):
    """Stage object writes of *repo* until :func:`flush` (or the block's end).

    Nested batches join the outer one. An exception discards what was staged:
    nothing of a failed run reaches the disk.
    """
    if staged(repo) is not None or _pack_version(repo) is None:
        yield
        return
    repo.__dict__[_KEY] = {}
    try:
        yield
        flush(repo)
    finally:
        repo.__dict__.pop(_KEY, None)


def flush(repo) -> str | None:
    """Make the staged objects durable; return the new pack's digest, if any."""
    objects = staged(repo)
    if not objects:
        return None
    items = sorted(objects.items())
    objects.clear()
    version = _pack_version(repo)
    if len(items) == 1 or version is None or len(items) > MAX_PACK_OBJECTS:
        from opentine.repository._storage import write_loose

        for oid, raw in items:
            write_loose(repo, oid, raw)
        return None
    from opentine.repository._pack_v3 import build_pack_v3
    from opentine.repository._pack_write import build_pack

    configured = getattr(repo, "_storage_codec", None)
    codec = configured if configured not in (None, "none") else _codec.default_codec()
    build = build_pack_v3 if version == 3 else build_pack
    digest, body, index = build(items, codec, None)
    publish_pack(repo.path, digest, body, index)
    return digest


def _staged_file(directory: Path, name: str, data: bytes) -> str:
    fd, temporary = tempfile.mkstemp(dir=directory, prefix=f".{name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            full_fsync(handle.fileno())
    except BaseException:
        os.unlink(temporary)
        raise
    return temporary


def publish_pack(root: Path, digest: str, body: bytes, index: bytes) -> None:
    """Install one pack: each file synced once, the directory synced once.

    The body is renamed in first; the index rename is what makes readers see
    the pack, and it lands only once both files' bytes are durable.
    """
    directory = internal_path(root, "packs")
    durable_directory(directory)
    temps: list[str] = []
    try:
        for suffix, data in ((".tpk", body), (".tidx", index)):
            temps.append(_staged_file(directory, digest + suffix, data))
        for temporary, suffix in zip(temps, (".tpk", ".tidx"), strict=True):
            _winretry.replace(temporary, directory / f"{digest}{suffix}")
        _fsync_dir(directory)
    finally:
        for temporary in temps:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
