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
from collections import OrderedDict
from pathlib import Path

from opentine import _codec
from opentine.kernel import KernelError, object_id
from opentine.repository import _pack_v3_index as v3index
from opentine.repository._pack_index import (  # noqa: F401 -- re-exported
    BLOCK_BYTES,
    MAX_INDEX_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PACK_OBJECTS,
    PACK_MAGIC,
    _block_sizes,
    _parse_index,
)
from opentine.repository._paths import internal_path

#: Inflated blocks kept per repository; v3 blocks are up to 16 MiB each.
CACHE_BYTES = 64 * 1024 * 1024
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


class PackSet:
    """The packs of one repository, loaded once and refreshed on a miss."""

    def __init__(self, root: Path):
        self.root = root
        self.fingerprint: tuple | None = None
        self.where: dict[str, tuple[str, int, int, int]] = {}
        self.blocks: dict[str, list] = {}
        #: v3 packs only: digest -> oid -> (block, start, length, size, encoding)
        self.v3: dict[str, dict[str, tuple[int, int, int, int, int]]] = {}
        self._recent: OrderedDict[tuple[str, int], bytes] = OrderedDict()
        self._ends: dict[str, dict[tuple[int, int], str]] = {}

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
        v3: dict[str, dict] = {}
        for name, _, _ in fingerprint:
            digest = name[:64]
            try:
                table, entries, version = load_index(self.root, digest)
            except (OSError, ValueError):  # KernelError and CodecError included
                continue  # its objects read as missing; fsck names the broken pack
            blocks[digest] = table
            if version == 3:
                v3[digest] = entries
            for oid, place in entries.items():
                where.setdefault(oid, (digest, *place[:3]))
        self.fingerprint, self.where, self.blocks, self.v3 = fingerprint, where, blocks, v3
        self._recent.clear()
        self._ends = {}

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
            data = _codec.unwrap(stored, limit=size)
            while self._recent and (
                len(self._recent) >= 16
                or sum(map(len, self._recent.values())) + len(data) > CACHE_BYTES
            ):
                self._recent.popitem(last=False)
            self._recent[key] = data
        self._recent.move_to_end(key)
        return self._recent[key]

    def size(self, oid: str) -> int | None:
        """Canonical size of a packed object (stored length is not it in v3)."""
        found = self.locate(oid)
        if found is None:
            return None
        entry = self.v3.get(found[0], {}).get(oid)
        return found[3] if entry is None else entry[3]

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
        digest = found[0]
        if digest in self.v3:
            from opentine.repository._pack_v3 import resolve

            return resolve(oid, lambda key: self._stored3(digest, key))
        _, number, start, length = found
        raw = self._slice(digest, number, start, length, oid)
        if oid_of(raw) != oid:
            raise KernelError(f"packed object does not match its id: {oid}")
        return raw

    def _slice(self, digest: str, number: int, start: int, length: int, oid: str) -> bytes:
        data = self.block(digest, number)
        if start + length > len(data):
            raise KernelError(f"pack index points past its block: {oid}")
        return data[start : start + length]

    def _stored3(self, digest: str, oid: str) -> tuple[bytes, int, int, str | None]:
        number, start, length, size, encoding = self.v3[digest][oid]
        before = None
        if encoding == 1 and start:  # RUN_DELTA: its base is the object stored before it
            if digest not in self._ends:
                ends = {(e[0], e[1] + e[2]): key for key, e in self.v3[digest].items()}
                self._ends = {digest: ends}  # one pack's map at a time
            before = self._ends[digest].get((number, start))
        return self._slice(digest, number, start, length, oid), encoding, size, before

    def in_block_order(self, oids: list[str] | None = None) -> list[str]:
        """*oids* (default: all) ordered so each block is inflated once in a pass."""
        chosen = list(self.where) if oids is None else [o for o in oids if o in self.where]
        return sorted(chosen, key=lambda oid: self.where[oid])

    def oids(self, object_types: set[str] | None = None) -> list[str]:
        self.refresh()
        if object_types is None:
            return sorted(self.where)
        return sorted(oid for oid in self.where if oid.split(":", 1)[0] in object_types)


def load_index(root: Path, digest: str) -> tuple[list, dict, int]:
    """(block table, entries, pack version) of one pack, whichever its format."""
    tpk = internal_path(root, "packs", f"{digest}.tpk")
    data = _read_file(internal_path(root, "packs", f"{digest}.tidx"), limit=MAX_INDEX_BYTES)
    if data.startswith(v3index.INDEX_MAGIC):
        table, entries = v3index.parse_index(data, digest, tpk.stat().st_size)
        return table, entries, 3
    table, entries = _parse_index(data, digest, tpk.stat().st_size)
    return table, entries, 1


def pack_set(root: Path) -> PackSet:
    key = str(root)
    if key not in _CACHE:
        _CACHE[key] = PackSet(root)
    return _CACHE[key]
