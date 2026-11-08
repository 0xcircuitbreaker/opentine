"""O(log n) appends to an ``opentine-log/1`` tile log (0.45; ``docs/design/log-2.md``).

The 0.44 append re-read and re-hashed every entry, so a log of n entries cost
O(n) per append. The tile layout already holds everything an append needs: the
right edge of the tree. This module

1. opens the signed checkpoint (size n, root R) under the log's lock;
2. recomputes R from the hash tiles alone (:class:`_tlog_proof.Hashes`, at most
   ~256 hashes per tile level) and checks the last entry against its leaf hash,
   so an append never extends a right edge the checkpoint does not sign;
3. writes the one changed entry bundle and, per tile level, the one changed
   partial tile (a level gains a hash only when the level below fills a tile);
4. signs the new checkpoint last -- the commit point, exactly as before.

Bytes on disk are identical to :func:`_tlog.write_tiles` (a test pins that), so
the format stays ``opentine-log/1``. Full verification of every entry remains
:func:`_tlog_note.verify_log` (``tine log verify``), not the append path.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from opentine.repository import _tlog, _tlog_note, _tlog_proof
from opentine.repository._paths import atomic_bytes
from opentine.repository._tlog import TILE_WIDTH, LogError, tile_path


def _reader(root: Path) -> Callable[[str], bytes]:
    return lambda rel: _tlog._read(root, rel)


def _last_entry(root: Path, size: int, hashes: _tlog_proof.Hashes) -> list[bytes]:
    if size == 0:
        return []
    index = (size - 1) // TILE_WIDTH
    width = size - index * TILE_WIDTH
    entries = _tlog.unbundle(_tlog._read(root, tile_path("entries", index, width)), width)
    if _tlog.leaf_hash(entries[-1]) != hashes.node(0, size - 1):
        raise LogError("the last entry does not match its leaf hash")
    return [entries[-1]]


def _partial(root: Path, level: str | int, count: int) -> bytes:
    """The stored bytes of the (possibly empty) partial tile at the end of a level."""
    width = count % TILE_WIDTH
    if width == 0:
        return b""
    return _tlog._read(root, tile_path(level, count // TILE_WIDTH, width))


def write_append(root: Path, size: int, entry: bytes) -> None:
    """Write the entry bundle and hash tiles that appending ``entry`` at ``size`` changes."""
    new = size + 1
    first = size // TILE_WIDTH
    bundle = _partial(root, "entries", size) + _tlog.bundle([entry])
    _tlog._put(root, tile_path("entries", first, new - first * TILE_WIDTH), bundle)
    value, level = _tlog.leaf_hash(entry), 0
    while True:
        old_count, new_count = size >> (8 * level), new >> (8 * level)
        if new_count == old_count:
            return
        tile = _partial(root, level, old_count) + value
        index = old_count // TILE_WIDTH
        _tlog._put(root, tile_path(level, index, new_count - index * TILE_WIDTH), tile)
        if len(tile) < 32 * TILE_WIDTH:
            return
        row = [tile[i : i + 32] for i in range(0, len(tile), 32)]
        value, level = _tlog.merkle_root(row), level + 1


def append(root: Path, origin: str, make: Callable[[list[bytes]], bytes]) -> int:
    """Append ``make(tail)`` (``tail`` = ``[last entry]`` or ``[]``); return its index."""
    with _tlog.log_lock(root):
        private = _tlog_note._signer(root, origin)
        size, tree_root = 0, _tlog.merkle_root([])
        path = root / "checkpoint"
        if path.exists():
            note = path.read_bytes()
            log_origin, size, tree_root = _tlog_note.open_checkpoint(
                note, _tlog_note.stored_vkey(root)
            )
            if log_origin != origin:
                raise LogError("checkpoint names another log")
            if size >= _tlog.MAX_LOG_ENTRIES:
                raise LogError("log is full")
        hashes = _tlog_proof.Hashes(size, _reader(root))
        if hashes.root() != tree_root:
            raise LogError("log tiles do not match the signed checkpoint root")
        entry = make(_last_entry(root, size, hashes))
        if len(entry) > _tlog.MAX_ENTRY_BYTES:
            raise LogError("log entry exceeds 65535 bytes")
        write_append(root, size, entry)
        new_root = _tlog_proof.Hashes(size + 1, _reader(root)).root()
        atomic_bytes(path, _tlog_note.sign_checkpoint(private, origin, size + 1, new_root))
        return size


__all__ = ["append", "write_append"]
