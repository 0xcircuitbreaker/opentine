"""``opentine-log/1``: an append-only record log in the C2SP tlog-tiles layout.

A log lives in its own directory (``.tine/log/<name>/``) exactly as
https://c2sp.org/tlog-tiles lays out a static log: ``checkpoint`` (a signed note,
:mod:`._tlog_note`), ``tile/<L>/<N>[.p/<W>]`` (RFC 6962 Merkle hashes, 256 per
tile) and ``tile/entries/<N>[.p/<W>]`` (entry bundles: each entry prefixed by
its big-endian ``uint16`` length). The checkpoint is the commit point: tiles are
written first, so a crash leaves at worst unreferenced tile bytes the next
append overwrites. Readers trust only the size and root the signed checkpoint
names, and recompute both from the entries (:func:`verify_log`).
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.repository import _winretry
from opentine.repository._lockfile import acquire
from opentine.repository._paths import atomic_bytes, durable_directory

LOG_FORMAT = "opentine-log/1"
TILE_WIDTH = 256
MAX_ENTRY_BYTES = 0xFFFF
MAX_LOG_ENTRIES = 1 << 24  # a local log: the bound keeps a full read finite


class LogError(ValueError):
    """The log is malformed, tampered with, or does not match its checkpoint."""


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 MTH over leaf hashes (``SHA-256("")`` for the empty tree)."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    stack: list[tuple[int, bytes]] = []  # (subtree size, hash), sizes strictly decreasing
    for leaf in leaves:
        size, value = 1, leaf
        while stack and stack[-1][0] == size:
            value = _node(stack.pop()[1], value)
            size *= 2
        stack.append((size, value))
    value = stack.pop()[1]
    while stack:
        value = _node(stack.pop()[1], value)
    return value


def tile_path(level: str | int, index: int, width: int = TILE_WIDTH) -> str:
    """``tile/<L>/<N>[.p/<W>]`` with N in ``x``-prefixed three-digit groups."""
    digits = f"{index:d}"
    digits = digits.zfill(-(-len(digits) // 3) * 3)
    groups = [digits[i : i + 3] for i in range(0, len(digits), 3)]
    name = "/".join([*(f"x{g}" for g in groups[:-1]), groups[-1]])
    suffix = "" if width == TILE_WIDTH else f".p/{width}"
    return f"tile/{level}/{name}{suffix}"


def tile_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """Tile level L holds the Merkle hashes of every full 256**L-leaf subtree."""
    levels = [leaves]
    while len(levels[-1]) >= TILE_WIDTH:
        row = levels[-1]
        for _ in range(8):  # 8 Merkle levels per tile level
            row = [_node(row[i], row[i + 1]) for i in range(0, len(row) - 1, 2)]
        levels.append(row)
    return levels


def _tiles(size: int) -> list[tuple[int, int]]:
    """``(index, width)`` of every tile a level of ``size`` hashes is stored in."""
    return [(k, min(TILE_WIDTH, size - k * TILE_WIDTH)) for k in range(-(-size // TILE_WIDTH))]


def bundle(entries: list[bytes]) -> bytes:
    return b"".join(len(e).to_bytes(2, "big") + e for e in entries)


def unbundle(data: bytes, count: int) -> list[bytes]:
    entries, offset = [], 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise LogError("entry bundle is truncated")
        length = int.from_bytes(data[offset : offset + 2], "big")
        entries.append(data[offset + 2 : offset + 2 + length])
        offset += 2 + length
        if offset > len(data):
            raise LogError("entry bundle is truncated")
    if len(entries) != count:
        raise LogError(f"entry bundle holds {len(entries)} entries, expected {count}")
    return entries


def _read(root: Path, relative: str) -> bytes:
    try:
        return (root / relative).read_bytes()
    except FileNotFoundError as exc:
        raise LogError(f"log tile is missing: {relative}") from exc


def read_entries(root: Path, size: int) -> list[bytes]:
    """The first ``size`` entries, from the entry bundles a size-``size`` tree uses."""
    if not 0 <= size <= MAX_LOG_ENTRIES:
        raise LogError("log size is out of range")
    entries: list[bytes] = []
    for index, width in _tiles(size):
        entries.extend(unbundle(_read(root, tile_path("entries", index, width)), width))
    return entries


def check_tiles(root: Path, leaves: list[bytes]) -> None:
    """Every hash tile a tree of these leaves names must hold exactly its hashes."""
    for level, row in enumerate(tile_levels(leaves)):
        for index, width in _tiles(len(row)):
            expected = b"".join(row[index * TILE_WIDTH : index * TILE_WIDTH + width])
            if _read(root, tile_path(level, index, width)) != expected:
                raise LogError(f"hash tile {tile_path(level, index, width)} does not match")


def write_tiles(root: Path, entries: list[bytes], old_size: int) -> None:
    """Write the entry bundles and hash tiles the append from ``old_size`` changed."""
    leaves = [leaf_hash(e) for e in entries]
    first = old_size // TILE_WIDTH
    for index, width in _tiles(len(entries))[first:]:
        chunk = entries[index * TILE_WIDTH : index * TILE_WIDTH + width]
        _put(root, tile_path("entries", index, width), bundle(chunk))
    for level, row in enumerate(tile_levels(leaves)):
        start = (old_size >> (8 * level)) // TILE_WIDTH
        for index, width in _tiles(len(row))[start:]:
            data = b"".join(row[index * TILE_WIDTH : index * TILE_WIDTH + width])
            _put(root, tile_path(level, index, width), data)


def _put(root: Path, relative: str, data: bytes) -> None:
    path = root / relative
    durable_directory(path.parent)
    atomic_bytes(path, data)


class log_lock:  # noqa: N801 - a context manager used like a function
    """The log's single-writer lock (a dead holder's lock is broken, a live one waited on)."""

    def __init__(self, root: Path, timeout: float = 10.0) -> None:
        self.path, self.timeout = root / "lock", timeout

    def __enter__(self) -> None:
        durable_directory(self.path.parent)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                os.close(acquire(self.path, 0o600))
                return
            except FileExistsError:
                if time.monotonic() > deadline:
                    raise LogError(f"log is locked by a concurrent writer ({self.path})")
                time.sleep(0.005)

    def __exit__(self, *_exc) -> None:
        _winretry.unlink(self.path)
        _fsync_dir(self.path.parent)
