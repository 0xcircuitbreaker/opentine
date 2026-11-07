"""Codec 4 (xz, 0.37): the archival codec, readable with the stdlib alone.

Kept apart from :mod:`opentine._codec` so the wrapper stays small. Decoding is
bounded like the other codecs: output stops one byte past the declared size,
and a memory limit refuses a frame whose dictionary costs more than any writer
uses (preset 9 needs 64 MiB).
"""

from __future__ import annotations

from typing import Any

MEMLIMIT = 256 << 20


def lzma_module() -> Any:
    try:
        import lzma  # optional in a Python built without liblzma

        return lzma
    except ImportError:
        return None


def compress(raw: bytes, level: int | None, error: type[Exception]) -> bytes:
    from opentine import _fips

    _fips.require("xz-crc64")  # the archival form's stdlib reader leans on xz's CRC64
    module = lzma_module()
    if module is None:
        raise error("xz is not available in this Python build")
    preset = 6 if level is None else max(0, min(level, 9))
    return module.compress(raw, format=module.FORMAT_XZ, preset=preset)


def decompress(frame: bytes, size: int, error: type[Exception]) -> bytes:
    module = lzma_module()
    if module is None:
        raise error("this file is xz-compressed and this Python has no lzma module")
    engine = module.LZMADecompressor(format=module.FORMAT_XZ, memlimit=MEMLIMIT)
    try:
        out = engine.decompress(frame, size + 1)
    except module.LZMAError as exc:
        raise error("compressed body is corrupt") from exc
    if not engine.eof or engine.unused_data:
        raise error("compressed body has trailing or missing data")
    return out
