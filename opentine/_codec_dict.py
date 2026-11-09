"""Codec 3: zstd with a trained dictionary, a stored form for local packs (0.50, P3).

The frame of a codec-3 body is ``sha256(dictionary) | zstd frame``: the
dictionary is named by the digest of its bytes, so a reader looks it up by
content and refuses one whose bytes do not hash to that name. A body never
carries its dictionary; the repository keeps it (``_pack_dicts``).

Like every stored form this is reversible and never part of an identity: a
pack block in codec 3 inflates to the same stored objects as one in codec 2,
and each object is still checked against its id on read. Only local storage-v3
packs use it, behind a descriptor opt-in; transfer packs, bundles and ``.tine``
files are built from canonical objects and never carry it (SPEC §2.3).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

DICT = 3
ID_BYTES = 32
#: Largest dictionary a reader loads: zstd's own default is 110 KiB.
MAX_DICT_BYTES = 1 << 20

#: Looks a dictionary up by its sha256 digest: its bytes, or ``None``.
Lookup = Callable[[bytes], "bytes | None"]


def dict_id(content: bytes) -> bytes:
    return hashlib.sha256(content).digest()


def _module(error: type[Exception]) -> Any:
    from opentine._codec import _zstd

    module = _zstd()
    if module is None:
        raise error("this pack uses zstd dictionaries; install opentine[zstd] or use Python 3.14")
    return module


def train(samples: list[bytes], size: int) -> bytes | None:
    """A zstd dictionary of at most *size* bytes trained on *samples*, or ``None``.

    ``None`` when zstd is missing or the samples are too few or too alike for
    zstd to train on: the caller then writes plain codec 2 blocks.
    """
    from opentine._codec import _zstd

    module = _zstd()
    if module is None or not samples:
        return None
    try:
        return bytes(module.train_dict(samples, size).dict_content)
    except (module.ZstdError, ValueError):
        return None


def compress(raw: bytes, dictionary: bytes, level: int | None, error: type[Exception]) -> bytes:
    module = _module(error)
    table = module.ZstdDict(dictionary)
    frame = module.compress(raw, level=3 if level is None else level, zstd_dict=table)
    return dict_id(dictionary) + frame


def decompress(frame: bytes, size: int, lookup: Lookup | None, error: type[Exception]) -> bytes:
    """The body of a codec-3 *frame*, with the dictionary *lookup* finds by its id."""
    if len(frame) <= ID_BYTES:
        raise error("compressed body is truncated")
    wanted, frame = frame[:ID_BYTES], frame[ID_BYTES:]
    content = lookup(wanted) if lookup is not None else None
    if content is None:
        raise error(
            f"this body needs zstd dictionary sha256:{wanted.hex()}, which is not here "
            "(dictionary packs are local only; `tine gc --no-dictionaries` rewrites them)"
        )
    if len(content) > MAX_DICT_BYTES or dict_id(content) != wanted:
        raise error(f"zstd dictionary sha256:{wanted.hex()} does not match its id")
    module = _module(error)
    engine = module.ZstdDecompressor(zstd_dict=module.ZstdDict(content))
    try:
        out = engine.decompress(frame, size + 1)
    except module.ZstdError as exc:
        raise error("compressed body is corrupt") from exc
    if not engine.eof or engine.unused_data:
        raise error("compressed body has trailing or missing data")
    return out
