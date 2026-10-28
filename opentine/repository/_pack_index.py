"""The JSON ``.tidx`` of a version-1 local pack (see ``_packs``)."""

from __future__ import annotations

import json

from opentine import _codec
from opentine.kernel import KernelError, parse_oid

PACK_MAGIC = b"TINELP1\n"
BLOCK_BYTES = 1024 * 1024
MAX_OBJECT_BYTES = 256 * 1024 * 1024
MAX_INDEX_BYTES = 128 * 1024 * 1024
MAX_PACK_OBJECTS = 4_000_000


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
