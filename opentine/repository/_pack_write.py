"""Building, publishing and checking local packs (see ``_packs``)."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from opentine import _codec
from opentine.kernel import KernelError, canonical_json
from opentine.repository._packs import (
    _NAME,
    BLOCK_BYTES,
    MAX_INDEX_BYTES,
    PACK_MAGIC,
    PackSet,
    _parse_index,
    _read_file,
)
from opentine.repository._paths import atomic_bytes, internal_path


def build_pack(
    objects: list[tuple[str, bytes]], codec: str, level: int | None
) -> tuple[str, bytes, bytes]:
    """Pack *objects* (sorted by id): return (digest, ``.tpk`` bytes, ``.tidx`` bytes)."""
    body = bytearray(PACK_MAGIC)
    blocks: list[list[int]] = []
    entries: list[list[object]] = []
    pending: list[tuple[str, bytes]] = []

    def flush() -> None:
        if not pending:
            return
        offset = 0
        for oid, data in pending:
            entries.append([oid, len(blocks), offset, len(data)])
            offset += len(data)
        raw = b"".join(data for _, data in pending)
        stored = _codec.wrap(raw, codec, level=level, force=True)
        blocks.append([len(body), len(stored)])
        body.extend(stored)
        pending.clear()

    size = 0
    for oid, data in objects:
        if pending and size + len(data) > BLOCK_BYTES:
            flush()
            size = 0
        pending.append((oid, data))
        size += len(data)
    flush()
    digest = hashlib.sha256(body).hexdigest()
    index = canonical_json({"blocks": blocks, "objects": entries, "pack": digest, "version": 1})
    return digest, bytes(body), _codec.wrap(index, codec, force=True)


def write_pack(root: Path, objects: list[tuple[str, bytes]], codec: str, level: int | None) -> str:
    """Write *objects* as one pack (body first, then the index that publishes it)."""
    digest, body, index = build_pack(objects, codec, level)
    atomic_bytes(internal_path(root, "packs", f"{digest}.tpk"), body)
    atomic_bytes(internal_path(root, "packs", f"{digest}.tidx"), index)
    return digest


def load_pack(root: Path, digest: str) -> PackSet:
    """A reader over exactly one pack, for checking it before it is trusted."""
    body_path = internal_path(root, "packs", f"{digest}.tpk")
    data = _read_file(internal_path(root, "packs", f"{digest}.tidx"), limit=MAX_INDEX_BYTES)
    blocks, entries = _parse_index(data, digest, body_path.stat().st_size)
    single = PackSet(root)
    single.fingerprint, single.blocks = (), {digest: blocks}
    single.where = {oid: (digest, *place) for oid, place in entries.items()}
    return single


def _file_digest(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise KernelError("pack file is not a regular file")
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def verify_packs(root: Path) -> list[str]:
    """fsck: every index parses and covers its pack; every object matches its id."""
    errors: list[str] = []
    directory = internal_path(root, "packs")
    try:
        names = sorted(name for name in os.listdir(directory) if _NAME.fullmatch(name))
    except FileNotFoundError:
        return errors
    digests = {name[:64] for name in names}
    for digest in sorted(digests):
        tpk, tidx = f"{digest}.tpk", f"{digest}.tidx"
        if tpk not in names or tidx not in names:
            errors.append(f"pack {digest}: missing its {'.tpk' if tpk not in names else '.tidx'}")
            continue
        try:
            body_path = internal_path(root, "packs", tpk)
            if _file_digest(body_path) != digest:
                raise KernelError("pack file does not match its name")
            single = load_pack(root, digest)
            for oid in single.in_block_order():
                single.read(oid)
        except (KernelError, OSError, ValueError) as exc:
            errors.append(f"pack {digest}: {exc}")
    return errors
