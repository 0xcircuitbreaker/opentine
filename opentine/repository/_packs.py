"""Local packfiles: many small objects in a few compressed files.

Most objects are far smaller than a filesystem block, so a loose store spends
most of its disk on padding, and compressing each object alone finds little to
remove. ``tine gc`` therefore moves loose objects into a pack: a ``.tpk`` file of
compressed blocks (each about 1 MiB of concatenated canonical objects, so the
codec sees the repetition between them) and a ``.tidx`` index of where every
object sits. Both are named by the SHA-256 of the ``.tpk`` bytes.

An object read from a pack is checked against its id before it is returned,
exactly as a loose one is, and every block inflates under the codec's limits.
The index is a cache of positions, never an authority: a lookup it gets wrong
fails the id check instead of returning the wrong object.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from opentine import _codec
from opentine.kernel import KernelError, object_id, parse_oid
from opentine.repository._paths import internal_path

PACK_MAGIC = b"TINELP1\n"
BLOCK_BYTES = 1024 * 1024
MAX_OBJECT_BYTES = 256 * 1024 * 1024
MAX_INDEX_BYTES = 128 * 1024 * 1024
MAX_PACK_OBJECTS = 4_000_000
_NAME = re.compile(r"^([0-9a-f]{64})\.(tpk|tidx)$")
_CACHE: dict[str, PackSet] = {}


def oid_of(raw: bytes) -> str:
    """The id a canonical envelope hashes to (the header is parsed, not trusted)."""
    try:
        header_line, body = raw.split(b"\n", 1)
        header = json.loads(header_line) if len(header_line) <= 256 else None
    except (ValueError, RecursionError) as exc:
        raise KernelError("malformed object envelope") from exc
    if not isinstance(header, dict):
        raise KernelError("malformed object envelope")
    return object_id(str(header.get("type")), header.get("schema"), body)


def _read_file(path: Path, offset: int = 0, length: int | None = None, *, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise KernelError("pack file is not a regular file")
        handle.seek(offset)
        size = info.st_size - offset if length is None else length
        if size > limit:
            raise KernelError("pack read exceeds its size limit")
        data = handle.read(size)
    if len(data) != size:
        raise KernelError("pack file is truncated")
    return data


def _parse_index(data: bytes, digest: str, pack_size: int) -> tuple[list, dict]:
    try:
        index = json.loads(_codec.unwrap(data, limit=MAX_INDEX_BYTES))
    except (ValueError, RecursionError) as exc:
        raise KernelError("pack index is malformed") from exc
    if not isinstance(index, dict) or index.get("version") != 1 or index.get("pack") != digest:
        raise KernelError("pack index does not describe its pack")
    blocks, objects = index.get("blocks"), index.get("objects")
    if not isinstance(blocks, list) or not isinstance(objects, list):
        raise KernelError("pack index is malformed")
    if len(objects) > MAX_PACK_OBJECTS:
        raise KernelError("pack index lists too many objects")
    cursor = len(PACK_MAGIC)
    for block in blocks:
        if (
            not isinstance(block, list)
            or len(block) != 2
            or any(type(value) is not int for value in block)
            or block[0] != cursor
            or block[1] < 1
        ):
            raise KernelError("pack index block table is malformed")
        cursor += block[1]
    if cursor != pack_size:
        raise KernelError("pack index does not cover its pack exactly")
    entries: dict[str, tuple[int, int, int]] = {}
    previous = ""
    for entry in objects:
        if not isinstance(entry, list) or len(entry) != 4 or not isinstance(entry[0], str):
            raise KernelError("pack index entry is malformed")
        oid, block, start, length = entry
        parse_oid(oid)
        if oid <= previous:
            raise KernelError("pack index entries are not sorted and unique")
        previous = oid
        if any(type(value) is not int or value < 0 for value in (block, start, length)):
            raise KernelError("pack index entry is malformed")
        if block >= len(blocks) or length > MAX_OBJECT_BYTES:
            raise KernelError("pack index entry points outside its pack")
        entries[oid] = (block, start, length)
    sizes = _block_sizes(entries, len(blocks))
    return [[*block, size] for block, size in zip(blocks, sizes, strict=True)], entries


def _block_sizes(entries: dict[str, tuple[int, int, int]], count: int) -> list[int]:
    """Each block's exact inflated size, from entries that must tile it.

    A block's objects sit back to back from offset 0 with no gaps or overlaps,
    so its size is the sum of their lengths and nothing else may hide in it. A
    block of several objects stays within ``BLOCK_BYTES``, as the writer makes
    it: only a single large object gets a block of its own. A crafted index
    therefore cannot make a read of one small object inflate a huge block.
    """
    spans: list[list[tuple[int, int]]] = [[] for _ in range(count)]
    for block, start, length in entries.values():
        spans[block].append((start, length))
    sizes = []
    for items in spans:
        items.sort()
        cursor = 0
        for start, length in items:
            if start != cursor:
                raise KernelError("pack index block entries do not tile their block")
            cursor += length
        if not items or (len(items) > 1 and cursor > BLOCK_BYTES):
            raise KernelError("pack index block is empty or oversized")
        sizes.append(cursor)
    return sizes


class PackSet:
    """The packs of one repository, loaded once and refreshed on a miss."""

    def __init__(self, root: Path):
        self.root = root
        self.fingerprint: tuple | None = None
        self.where: dict[str, tuple[str, int, int, int]] = {}
        self.blocks: dict[str, list] = {}
        self._recent: dict[tuple[str, int], bytes] = {}

    def _scan(self) -> tuple:
        directory = internal_path(self.root, "packs")
        try:
            with os.scandir(directory) as stream:
                found = []
                for entry in stream:
                    if _NAME.fullmatch(entry.name) and entry.name.endswith(".tidx"):
                        info = entry.stat(follow_symlinks=False)
                        found.append((entry.name, info.st_size, info.st_mtime_ns))
        except FileNotFoundError:
            return ()
        return tuple(sorted(found))

    def refresh(self) -> None:
        fingerprint = self._scan()
        if fingerprint == self.fingerprint:
            return
        where: dict[str, tuple[str, int, int, int]] = {}
        blocks: dict[str, list] = {}
        for name, _, _ in fingerprint:
            digest = name[:64]
            tpk = internal_path(self.root, "packs", f"{digest}.tpk")
            try:
                data = _read_file(internal_path(self.root, "packs", name), limit=MAX_INDEX_BYTES)
                table, entries = _parse_index(data, digest, tpk.stat().st_size)
            except (OSError, ValueError):  # KernelError and CodecError included
                continue  # its objects read as missing; fsck names the broken pack

            blocks[digest] = table
            for oid, (block, start, length) in entries.items():
                where.setdefault(oid, (digest, block, start, length))
        self.fingerprint, self.where, self.blocks = fingerprint, where, blocks
        self._recent.clear()

    def locate(self, oid: str) -> tuple[str, int, int, int] | None:
        if self.fingerprint is None:
            self.refresh()
        found = self.where.get(oid)
        if found is None:
            self.refresh()
            found = self.where.get(oid)
        return found

    def block(self, digest: str, number: int) -> bytes:
        key = (digest, number)
        if key not in self._recent:
            offset, length, size = self.blocks[digest][number]
            path = internal_path(self.root, "packs", f"{digest}.tpk")
            stored = _read_file(path, offset, length, limit=MAX_OBJECT_BYTES + 64)
            if _codec.declared_size(stored) != size:
                raise KernelError("pack block size does not match its index")
            if len(self._recent) >= 4:
                self._recent.pop(next(iter(self._recent)))
            self._recent[key] = _codec.unwrap(stored, limit=size)
        return self._recent[key]

    def read(self, oid: str) -> bytes | None:
        try:
            return self._read(oid)
        except (FileNotFoundError, KeyError):
            # Another process repacked: the pack this process remembered is gone.
            self.fingerprint = None
            self.refresh()
            return self._read(oid)

    def _read(self, oid: str) -> bytes | None:
        found = self.locate(oid)
        if found is None:
            return None
        digest, number, start, length = found
        data = self.block(digest, number)
        if start + length > len(data):
            raise KernelError(f"pack index points past its block: {oid}")
        raw = data[start : start + length]
        if oid_of(raw) != oid:
            raise KernelError(f"packed object does not match its id: {oid}")
        return raw

    def in_block_order(self, oids: list[str] | None = None) -> list[str]:
        """*oids* (default: all) ordered so each block is inflated once in a pass."""
        chosen = list(self.where) if oids is None else [o for o in oids if o in self.where]
        return sorted(chosen, key=lambda oid: self.where[oid])

    def oids(self, object_types: set[str] | None = None) -> list[str]:
        self.refresh()
        if object_types is None:
            return sorted(self.where)
        return sorted(oid for oid in self.where if oid.split(":", 1)[0] in object_types)


def pack_set(root: Path) -> PackSet:
    key = str(root)
    if key not in _CACHE:
        _CACHE[key] = PackSet(root)
    return _CACHE[key]
