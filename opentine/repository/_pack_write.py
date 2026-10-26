"""Building, publishing and checking local packs (see ``_packs``)."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from opentine import _codec
from opentine.kernel import KernelError, canonical_json
from opentine.repository._config import read_config, storage_version
from opentine.repository._pack_v3 import build_pack_v3
from opentine.repository._pack_v3_index import PACK3_MAGIC
from opentine.repository._packs import (
    _NAME,
    BLOCK_BYTES,
    PACK_MAGIC,
    PackSet,
    _read_file,
    load_index,
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


def write_pack(
    root: Path,
    objects: list[tuple[str, bytes]],
    codec: str,
    level: int | None,
    version: int = 1,
) -> str:
    """Write *objects* as one pack (body first, then the index that publishes it).

    *version* 3 writes the storage-v3 pack (``_pack_v3``); only a repository
    whose descriptor is version 3 may hold one.
    """
    build = build_pack_v3 if version == 3 else build_pack
    digest, body, index = build(objects, codec, level)
    atomic_bytes(internal_path(root, "packs", f"{digest}.tpk"), body)
    atomic_bytes(internal_path(root, "packs", f"{digest}.tidx"), index)
    return digest


def load_pack(root: Path, digest: str) -> PackSet:
    """A reader over exactly one pack, for checking it before it is trusted."""
    blocks, entries, version = load_index(root, digest)
    single = PackSet(root)
    single.fingerprint, single.blocks = (), {digest: blocks}
    single.where = {oid: (digest, *place[:3]) for oid, place in entries.items()}
    single.v3 = {digest: entries} if version == 3 else {}
    return single


def pack_version(root: Path, digest: str) -> int:
    """1 or 3, from the ``.tpk`` magic (the index must agree)."""
    head = _read_file(internal_path(root, "packs", f"{digest}.tpk"), 0, 8, limit=8)
    if head not in (PACK_MAGIC, PACK3_MAGIC):
        raise KernelError("pack file has an unknown magic")
    return 3 if head == PACK3_MAGIC else 1


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
    v3_allowed = storage_version(read_config(internal_path(root, "config.json"))) == 3
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
            version = pack_version(root, digest)
            if version != (3 if single.v3 else 1):
                raise KernelError("pack file and index formats differ")
            if version == 3 and not v3_allowed:
                raise KernelError(
                    "storage-v3 pack in a repository below storage version 3 (opentine "
                    "0.12 cannot read it); rerun `tine gc --downgrade` or `tine gc --upgrade`"
                )
            for oid in single.in_block_order():
                single.read(oid)
        except (KernelError, OSError, ValueError) as exc:
            errors.append(f"pack {digest}: {exc}")
    return errors
