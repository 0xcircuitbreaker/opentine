"""The binary ``.tidx`` of a version-3 pack (SPEC 2.8, "Pack v3").

Layout, all integers big-endian::

    "TINEIX3\\n"  pack sha256 (32)  u32 blocks  u32 objects
    blocks  x (u32 stored length, u32 inflated length, u8 kind)
    objects x (u8 kind, 32-byte digest, u32 block, u32 start, u32 stored length,
               u32 canonical size, u8 encoding)
    sha256 of every byte above (32)

Objects are sorted by id (kind codes follow the alphabetical order of the type
names, so byte order is id order). A block holds one kind; its objects tile it
from offset 0; its inflated length is bounded (``MAX_BLOCK_BYTES``, or one
object's ``MAX_OBJECT_BYTES`` when it is alone). Every rule is checked before
anything is allocated from a count, and the trailing digest refuses a torn or
edited index before any field is trusted.
"""

from __future__ import annotations

import hashlib
import struct

from opentine.kernel import KernelError
from opentine.repository._run_delta import ENCODINGS, EVENT_SLIM, FULL, RUN_DELTA

INDEX_MAGIC = b"TINEIX3\n"
PACK3_MAGIC = b"TINELP3\n"
KINDS = ("annotation", "attestation", "blob", "event", "run")
MAX_BLOCK_BYTES = 16 * 1024 * 1024
MAX_OBJECT_BYTES = 256 * 1024 * 1024
MAX_PACK_OBJECTS = 4_000_000
_HEAD = struct.Struct(">8s32sII")
_BLOCK = struct.Struct(">IIB")
_ENTRY = struct.Struct(">B32sIIIIB")
_ALLOWED = {FULL: set(KINDS), RUN_DELTA: {"run"}, EVENT_SLIM: {"event"}}


def encode_index(digest: str, blocks: list[tuple[int, int, int]], entries: list[tuple]) -> bytes:
    """*blocks* as (stored, inflated, kind); *entries* as (oid, block, start, length, size, enc)."""
    out = bytearray(_HEAD.pack(INDEX_MAGIC, bytes.fromhex(digest), len(blocks), len(entries)))
    for stored, inflated, kind in blocks:
        out += _BLOCK.pack(stored, inflated, kind)
    for oid, block, start, length, size, encoding in sorted(entries):
        kind, _, hexdigest = oid.split(":")
        out += _ENTRY.pack(
            KINDS.index(kind), bytes.fromhex(hexdigest), block, start, length, size, encoding
        )
    return bytes(out + hashlib.sha256(out).digest())


def parse_index(data: bytes, digest: str, pack_size: int) -> tuple[list, dict]:
    """(block table, entries) of a v3 index, every rule checked or ``KernelError``.

    The block table rows are ``[offset, stored, inflated]`` like a v1 index's;
    entries map oid -> ``(block, start, length, size, encoding)``.
    """
    if len(data) < _HEAD.size + 32 or not data.startswith(INDEX_MAGIC):
        raise KernelError("pack index is malformed")
    magic, packed, count, objects = _HEAD.unpack_from(data)
    if count > MAX_PACK_OBJECTS or objects > MAX_PACK_OBJECTS:
        raise KernelError("pack index lists too many objects")
    if len(data) != _HEAD.size + count * _BLOCK.size + objects * _ENTRY.size + 32:
        raise KernelError("pack index is truncated or has trailing bytes")
    if hashlib.sha256(data[:-32]).digest() != data[-32:]:
        raise KernelError("pack index checksum does not match")
    if packed.hex() != digest:
        raise KernelError("pack index does not describe its pack")
    cursor = len(PACK3_MAGIC)
    table, kinds = [], []
    for number in range(count):
        stored, inflated, kind = _BLOCK.unpack_from(data, _HEAD.size + number * _BLOCK.size)
        if stored < 1 or inflated < 1 or kind >= len(KINDS) or inflated > MAX_OBJECT_BYTES:
            raise KernelError("pack index block table is malformed")
        table.append([cursor, stored, inflated])
        kinds.append(kind)
        cursor += stored
    if cursor != pack_size:
        raise KernelError("pack index does not cover its pack exactly")
    base = _HEAD.size + count * _BLOCK.size
    entries: dict[str, tuple[int, int, int, int, int]] = {}
    spans: list[list[tuple[int, int]]] = [[] for _ in range(count)]
    previous = b""
    for number in range(objects):
        kind, raw, block, start, length, size, encoding = _ENTRY.unpack_from(
            data, base + number * _ENTRY.size
        )
        key = bytes([kind]) + raw
        if key <= previous:
            raise KernelError("pack index entries are not sorted and unique")
        previous = key
        if kind >= len(KINDS) or encoding not in ENCODINGS or KINDS[kind] not in _ALLOWED[encoding]:
            raise KernelError("pack index entry is malformed")
        if block >= count or kinds[block] != kind:
            raise KernelError("pack index entry points outside its pack")
        if length < 1 or size > MAX_OBJECT_BYTES or (encoding == FULL and length != size):
            raise KernelError("pack index entry sizes are inconsistent")
        if encoding == RUN_DELTA and start == 0:
            raise KernelError("pack index run delta has no base before it in its block")
        spans[block].append((start, length))
        entries[f"{KINDS[kind]}:sha256:{raw.hex()}"] = (block, start, length, size, encoding)
    for row, items in zip(table, spans, strict=True):
        _tile(row[2], items)
    return table, entries


def _tile(inflated: int, items: list[tuple[int, int]]) -> None:
    items.sort()
    cursor = 0
    for start, length in items:
        if start != cursor:
            raise KernelError("pack index block entries do not tile their block")
        cursor += length
    if not items or cursor != inflated:
        raise KernelError("pack index block is empty or its length is wrong")
    if len(items) > 1 and inflated > MAX_BLOCK_BYTES:
        raise KernelError("pack index block is oversized")
