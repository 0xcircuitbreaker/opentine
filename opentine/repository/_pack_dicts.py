"""Per-kind zstd dictionaries for local storage-v3 packs (0.50, roadmap P3).

In a repository opted in (``_gc_dicts``), every v3 pack gc writes trains one
zstd dictionary per object kind on the stored forms it is about to pack (the
corpus is the repository itself), keeps it only if it saves more than its own
size, and compresses that kind's blocks with it where they come out smaller
(codec 3, ``_codec_dict``). Each dictionary is kept content-addressed as
``dicts/<sha256>.zdict``; a block names the digest of its dictionary and a
reader refuses bytes that do not hash to it. Objects are still checked against
their id on every read, so ids and signatures do not change. gc deletes a
dictionary once no pack names it and it is not the latest for its kind.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from pathlib import Path

from opentine import _codec, _codec_dict
from opentine.kernel import KernelError, canonical_json
from opentine.repository._paths import atomic_bytes, internal_path

_DIR, _LATEST = "dicts", "kinds.json"
_NAME = re.compile(r"[0-9a-f]{64}\.zdict")
#: zstd's default dictionary size; a kind needs this much stored data to train.
DICT_BYTES = 112_640
MIN_TRAIN_BYTES = 2 * DICT_BYTES
MIN_SAMPLES = 16
#: Stored bytes a fresh dictionary is tried on before gc keeps it.
PROBE_BYTES = 4 << 20
#: Samples per kind and bytes per sample: training cost stays bounded.
MAX_SAMPLES, MAX_SAMPLE_BYTES = 4096, 128 * 1024


def _samples(stored: list[bytes]) -> list[bytes]:
    step = max(1, len(stored) // MAX_SAMPLES)
    return [data[:MAX_SAMPLE_BYTES] for data in stored[::step][:MAX_SAMPLES]]


def trainer(root: Path) -> Callable[[list], dict[str, bytes]]:
    """Train one dictionary per kind with enough stored data, else reuse the last.

    The trainer takes ``_pack_v3.stored_forms`` rows: (oid, stored bytes, ...).
    A small gc (a few new objects) has too little to train on, which is where a
    dictionary helps most, so it reuses the one the last training kept for that
    kind (``kinds.json``, a writer's hint only: readers find dictionaries by id).
    """

    def train(rows: list) -> dict[str, bytes]:
        by_kind: dict[str, list[bytes]] = {}
        for row in rows:
            by_kind.setdefault(row[0].split(":", 1)[0], []).append(row[1])
        latest, find = _latest(root), lookup(root)
        chosen: dict[str, bytes] = {}
        for kind, stored in sorted(by_kind.items()):
            content = None
            if len(stored) >= MIN_SAMPLES and sum(map(len, stored)) >= MIN_TRAIN_BYTES:
                content = _pays(_codec_dict.train(_samples(stored), DICT_BYTES), stored)
            if content is None and kind in latest:
                found = find(bytes.fromhex(latest[kind]))
                ok = found is not None and _codec_dict.dict_id(found).hex() == latest[kind]
                content = found if ok else None
            if content:
                latest[kind] = save(root, content)
                chosen[kind] = content
        if chosen:
            atomic_bytes(internal_path(root, _DIR, _LATEST), canonical_json(latest))
        return chosen

    return train


def _pays(content: bytes | None, stored: list[bytes]) -> bytes | None:
    """*content* if it saves more than its own size on *stored*, estimated on a sample.

    Kind-grouped 16 MiB blocks already find most repetition (the 0.37 bench
    measured long mode beating dictionaries), so a fresh dictionary must earn
    its keep before gc stores it; the writer still uses it only on blocks it
    makes smaller.
    """
    if content is None:
        return None
    total = sum(map(len, stored))
    sample = b"".join(stored)[:PROBE_BYTES] if total > PROBE_BYTES else b"".join(stored)
    plain = len(_codec.compress_frame(sample, "zstd", 3))
    framed = len(_codec_dict.compress(sample, content, 3, _codec.CodecError))
    return content if (plain - framed) * (total / max(len(sample), 1)) > len(content) else None


def _latest(root: Path) -> dict[str, str]:
    """``kinds.json``: the digest of the dictionary last trained for each kind."""
    try:
        value = json.loads(internal_path(root, _DIR, _LATEST).read_bytes()[:65536])
    except (OSError, ValueError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in value.items() if isinstance(v, str) and _NAME.fullmatch(v + ".zdict")}


def save(root: Path, content: bytes) -> str:
    """Keep *content* as ``dicts/<sha256>.zdict``; return the hex digest."""
    name = _codec_dict.dict_id(content).hex()
    path = internal_path(root, _DIR, f"{name}.zdict")
    if not path.is_file():
        path.parent.mkdir(exist_ok=True)
        atomic_bytes(path, content)
    return name


def lookup(root: Path) -> _codec_dict.Lookup:
    """Finds a dictionary of *root* by its digest (the codec checks the bytes)."""

    def find(wanted: bytes) -> bytes | None:
        path = internal_path(root, _DIR, f"{wanted.hex()}.zdict")
        try:
            with path.open("rb") as handle:
                return handle.read(_codec_dict.MAX_DICT_BYTES + 1)
        except (FileNotFoundError, IsADirectoryError):
            return None

    return find


def block_dict(stored_head: bytes) -> str | None:
    """The dictionary digest a stored block names, or ``None`` (not codec 3)."""
    if not _codec.is_wrapped(stored_head) or stored_head[len(_codec.MAGIC)] != _codec.DICT:
        return None
    _, start = _codec._read_uvarint(stored_head, len(_codec.MAGIC) + 1)
    wanted = stored_head[start : start + _codec_dict.ID_BYTES]
    if len(wanted) != _codec_dict.ID_BYTES:
        raise KernelError("pack block names a truncated dictionary id")
    return wanted.hex()


def referenced(root: Path) -> set[str]:
    """Every dictionary digest a v3 pack of *root* names."""
    from opentine.repository._packs import _NAME as PACK_NAME
    from opentine.repository._packs import _read_file, load_index

    directory = internal_path(root, "packs")
    names = sorted(os.listdir(directory)) if directory.is_dir() else []
    found: set[str] = set()
    for digest in sorted({name[:64] for name in names if PACK_NAME.fullmatch(name)}):
        table, _, version = load_index(root, digest)
        path = internal_path(root, "packs", f"{digest}.tpk")
        for row in table if version == 3 else ():
            head = _read_file(path, row[0], min(row[1], 64), limit=64)
            name = block_dict(head)
            if name:
                found.add(name)
    return found


def forget_latest(root: Path) -> None:
    """Drop the writer's hint (``--no-dictionaries``), so tidy can delete them all."""
    internal_path(root, _DIR, _LATEST).unlink(missing_ok=True)


def tidy(root: Path) -> int:
    """Delete dictionaries no pack names (gc, under its lock); return how many."""
    directory = internal_path(root, _DIR)
    if not directory.is_dir():
        return 0
    keep, removed = referenced(root) | set(_latest(root).values()), 0
    for name in sorted(os.listdir(directory)):
        if _NAME.fullmatch(name) and name[:64] not in keep:
            internal_path(root, _DIR, name).unlink(missing_ok=True)
            removed += 1
    return removed
