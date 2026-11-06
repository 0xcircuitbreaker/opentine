"""Pack index lookups without loading every entry (P7, 0.37).

A process used to parse every pack index into one ``oid -> place`` dict at its
first object read: seconds and hundreds of MB for millions of objects, paid by
``tine log`` as much as by gc. A version-3 ``.tidx`` is already a sorted table of
fixed-size records, so :class:`MappedIndex` maps it (``mmap``; read into memory
on Windows, where a mapped file could not be replaced or deleted by a gc) and
finds an object by binary search under a fanout table of its two leading key
bytes (kind code, first digest byte), built lazily from one strided copy.

What is checked at open: the header, the exact length, the trailing SHA-256 of
the whole file, and the block table against the pack's size -- everything that
does not scale with the object count. Each entry a lookup returns is checked
on its own (kind, encoding, block, sizes, and that it lies inside its block, a
block over ``MAX_BLOCK_BYTES`` holding exactly one object), so a crafted index
still cannot make one small read inflate a huge block. The whole-file rules
(entries sorted, unique and tiling their blocks) run in :meth:`entries`, which
bulk walks (gc, du, fsck's ``verify_packs``) use. As before, the index is never
an authority: an object read from a pack is checked against its id.

Version-1 JSON indexes (0.11-0.12) are still read, eagerly, as they always were.
"""

from __future__ import annotations

import hashlib
import mmap
import os
import stat
import struct
import sys
from array import array
from bisect import bisect_left
from pathlib import Path

from opentine.kernel import KernelError
from opentine.repository import _pack_v3_index as v3index
from opentine.repository._pack_index import MAX_INDEX_BYTES, _parse_index
from opentine.repository._paths import internal_path
from opentine.repository._run_delta import ENCODINGS, FULL, RUN_DELTA

#: Map indexes into memory (POSIX); Windows reads them (a mapping pins the file).
USE_MMAP = os.name != "nt"
_ENTRY = struct.Struct(">B32sIIIIB")
_KEY = 33
_BUCKETS = len(v3index.KINDS) * 256


def _read(path: Path) -> mmap.mmap | bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise KernelError("pack file is not a regular file")
        if info.st_size > MAX_INDEX_BYTES:
            raise KernelError("pack read exceeds its size limit")
        if USE_MMAP and info.st_size:
            return mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read(info.st_size + 1)
        if len(data) != info.st_size:
            raise KernelError("pack file is truncated")
        return data
    finally:
        os.close(fd)


class LegacyIndex:
    """A version-1 JSON index, parsed whole (what every release did)."""

    version = 1

    def __init__(self, table: list, entries: dict):
        self.table, self._entries = table, entries

    def find(self, oid: str) -> tuple | None:
        return self._entries.get(oid)

    def entries(self) -> dict:
        return self._entries

    def oids(self, kinds: set[str] | None) -> list[str]:
        return [oid for oid in self._entries if not kinds or oid.split(":")[0] in kinds]


class MappedIndex:
    """A version-3 index searched in place; entries are decoded one at a time."""

    version = 3

    def __init__(self, data, digest: str, pack_size: int):
        head = v3index._HEAD
        if len(data) < head.size + 32 or data[:8] != v3index.INDEX_MAGIC:
            raise KernelError("pack index is malformed")
        _, packed, count, objects = head.unpack_from(data)
        if count > v3index.MAX_PACK_OBJECTS or objects > v3index.MAX_PACK_OBJECTS:
            raise KernelError("pack index lists too many objects")
        size = head.size + count * v3index._BLOCK.size + objects * _ENTRY.size + 32
        if len(data) != size:
            raise KernelError("pack index is truncated or has trailing bytes")
        view = memoryview(data)
        if hashlib.sha256(view[:-32]).digest() != data[-32:]:
            raise KernelError("pack index checksum does not match")
        if packed.hex() != digest:
            raise KernelError("pack index does not describe its pack")
        self.data, self.digest, self.pack_size, self.objects = data, digest, pack_size, objects
        self.base = head.size + count * v3index._BLOCK.size
        cursor = len(v3index.PACK3_MAGIC)
        self.table, self.kinds = [], []
        for number in range(count):
            row = v3index._BLOCK.unpack_from(data, head.size + number * v3index._BLOCK.size)
            stored, inflated, kind = row
            if stored < 1 or inflated < 1 or kind >= len(v3index.KINDS):
                raise KernelError("pack index block table is malformed")
            if inflated > v3index.MAX_OBJECT_BYTES:
                raise KernelError("pack index block table is malformed")
            self.table.append([cursor, stored, inflated])
            self.kinds.append(kind)
            cursor += stored
        if cursor != pack_size:
            raise KernelError("pack index does not cover its pack exactly")
        self._fanout: list[int] | None = None

    def fanout(self) -> list[int]:
        """Entry numbers where each (kind, first digest byte) bucket starts."""
        if self._fanout is None:
            end = self.base + self.objects * _ENTRY.size
            view = memoryview(self.data)
            prefixes = bytearray(2 * self.objects)
            prefixes[0::2] = view[self.base : end : _ENTRY.size]
            prefixes[1::2] = view[self.base + 1 : end : _ENTRY.size]
            keys = array("H", prefixes)
            if sys.byteorder == "little":
                keys.byteswap()  # big-endian pairs sort as the index does
            self._fanout = [bisect_left(keys, bucket) for bucket in range(_BUCKETS)]
            self._fanout.append(self.objects)
        return self._fanout

    def find(self, oid: str) -> tuple[int, int, int, int, int] | None:
        kind, _, rest = oid.partition(":sha256:")
        if kind not in v3index.KINDS or len(rest) != 64:
            return None
        try:
            key = bytes([v3index.KINDS.index(kind)]) + bytes.fromhex(rest)
        except ValueError:
            return None
        bucket = key[0] * 256 + key[1]
        table = self.fanout()
        low, high = table[bucket], table[bucket + 1]
        while low < high:
            middle = (low + high) // 2
            offset = self.base + middle * _ENTRY.size
            probe = self.data[offset : offset + _KEY]
            if probe == key:
                return self._checked(_ENTRY.unpack_from(self.data, offset))
            low, high = (middle + 1, high) if probe < key else (low, middle)
        return None

    def _checked(self, row: tuple) -> tuple[int, int, int, int, int]:
        kind, _, block, start, length, size, encoding = row
        kinds = v3index._ALLOWED.get(encoding, ())
        if encoding not in ENCODINGS or v3index.KINDS[kind] not in kinds:
            raise KernelError("pack index entry is malformed")
        if block >= len(self.table) or self.kinds[block] != kind:
            raise KernelError("pack index entry points outside its pack")
        if length < 1 or size > v3index.MAX_OBJECT_BYTES or (encoding == FULL and length != size):
            raise KernelError("pack index entry sizes are inconsistent")
        if encoding == RUN_DELTA and start == 0:
            raise KernelError("pack index run delta has no base before it in its block")
        inflated = self.table[block][2]
        alone = start == 0 and length == inflated
        if start + length > inflated or (inflated > v3index.MAX_BLOCK_BYTES and not alone):
            raise KernelError("pack index entry does not fit its block")
        return block, start, length, size, encoding

    def oids(self, kinds: set[str] | None) -> list[str]:
        """The ids of every object of *kinds* (all when ``None``), read off the keys."""
        table, out = self.fanout(), []
        for code, kind in enumerate(v3index.KINDS):
            if kinds and kind not in kinds:
                continue
            for number in range(table[code * 256], table[code * 256 + 256]):
                offset = self.base + number * _ENTRY.size + 1
                out.append(f"{kind}:sha256:{self.data[offset : offset + 32].hex()}")
        return out

    def entries(self) -> dict:
        """Every entry, with every whole-file rule checked (bulk walks only)."""
        return v3index.parse_index(bytes(self.data), self.digest, self.pack_size)[1]


def open_index(root: Path, digest: str) -> LegacyIndex | MappedIndex:
    """The index of one pack, whichever its format; ``KernelError`` if it is bad."""
    tpk = internal_path(root, "packs", f"{digest}.tpk")
    data = _read(internal_path(root, "packs", f"{digest}.tidx"))
    if data[:8] == v3index.INDEX_MAGIC:
        return MappedIndex(data, digest, tpk.stat().st_size)
    table, entries = _parse_index(bytes(data), digest, tpk.stat().st_size)
    return LegacyIndex(table, entries)
