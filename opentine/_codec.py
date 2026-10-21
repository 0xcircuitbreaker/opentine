"""Storage compression: one wrapper, three codecs, hard limits on every read.

A compressed file or object is ``b"TINEZ1\\0" + codec byte + uvarint(raw length)
+ frame``. The declared raw length comes first so a reader can refuse an
oversized body before allocating it, and the magic cannot open a JSON document,
so a reader tells stored forms apart by their first bytes: anything else is the
legacy uncompressed form and is returned as it is.

Compression is a storage detail and never part of an identity. Object ids, run
digests and signatures are computed over the uncompressed canonical bytes, so a
file written raw by 0.3.0 and the same file written compressed by 0.11 are the
same artifact.

Codecs: 0 stores the bytes as they are, 1 is zlib (always available), 2 is
zstd (``compression.zstd`` on Python 3.14, the ``backports.zstd`` package on
3.11-3.13 via ``opentine[zstd]``). Writers fall back to zlib when zstd is
missing; a reader that meets zstd without it says how to install it.
"""

from __future__ import annotations

import os
import zlib
from typing import Any

MAGIC = b"TINEZ1\0"
RAW, ZLIB, ZSTD = 0, 1, 2
CODECS = {"raw": RAW, "zlib": ZLIB, "zstd": ZSTD}
NAMES = {value: key for key, value in CODECS.items()}

#: Largest raw-to-stored ratio a reader accepts. Writers never produce more:
#: a body that compresses further is stored as it is (``wrap`` returns ``None``).
MAX_RATIO = 1000
#: Bodies below this are stored as they are: a codec saves nothing on them.
MIN_COMPRESS_BYTES = 512
_MAX_VARINT_BYTES = 10
_ENV = "OPENTINE_COMPRESS"
_OFF = frozenset({"0", "off", "no", "false", "none", "raw"})


class CodecError(ValueError):
    """A stored body that cannot be decoded within the reader's limits."""


def _zstd() -> Any:
    try:
        from compression import zstd  # Python 3.14+

        return zstd
    except ImportError:
        pass
    try:
        from backports import zstd  # type: ignore[import-not-found]

        return zstd
    except ImportError:
        return None


def available(codec: str) -> bool:
    return codec in ("raw", "zlib") or (codec == "zstd" and _zstd() is not None)


def default_codec() -> str:
    return "zstd" if available("zstd") else "zlib"


def wanted(configured: str | None = None) -> str | None:
    """The codec a writer should use now, or ``None`` to store uncompressed.

    ``OPENTINE_COMPRESS=0`` (or ``off``) always wins: it is how a user writes
    files an older reader can open. ``OPENTINE_COMPRESS=zlib|zstd`` picks a
    codec; otherwise *configured* (a repository's setting) or the default.
    """
    value = os.environ.get(_ENV, "").strip().lower()
    if value in _OFF:
        return None
    if value in ("zlib", "zstd"):
        choice = value
    elif configured is not None:
        if configured == "none":
            return None
        choice = configured
    else:
        choice = default_codec()
    return choice if available(choice) else "zlib"


def is_wrapped(data: bytes) -> bool:
    return data[: len(MAGIC)] == MAGIC


def _uvarint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _read_uvarint(data: bytes, start: int) -> tuple[int, int]:
    value = shift = 0
    for index in range(start, min(len(data), start + _MAX_VARINT_BYTES)):
        byte = data[index]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if byte == 0 and index > start:
                raise CodecError("compressed header length is not minimally encoded")
            return value, index + 1
        shift += 7
    raise CodecError("compressed header length is malformed")


def compress_frame(raw: bytes, codec: str, level: int | None = None) -> bytes:
    if codec == "raw":
        return raw
    if codec == "zlib":
        return zlib.compress(raw, 6 if level is None else min(level, 9))
    if codec == "zstd":
        module = _zstd()
        if module is None:
            raise CodecError("zstd is not available; install opentine[zstd]")
        return module.compress(raw, level=3 if level is None else level)
    raise CodecError(f"unknown storage codec {codec!r}")


def wrap(raw: bytes, codec: str, *, level: int | None = None, force: bool = False) -> bytes | None:
    """*raw* in the wrapper, or ``None`` when compressing would not pay.

    ``None`` means "store it as it is": the body is small, did not shrink, or
    would compress past what a reader accepts (``MAX_RATIO``). ``force`` wraps
    regardless of size and gain (packs and archives, whose readers expect it).
    """
    if not force and len(raw) < MIN_COMPRESS_BYTES:
        return None
    frame = compress_frame(raw, codec, level)
    if len(raw) > max(len(frame), 1) * MAX_RATIO:
        if not force:
            return None
        frame, codec = raw, "raw"
    wrapped = MAGIC + bytes([CODECS[codec]]) + _uvarint(len(raw)) + frame
    if not force and len(wrapped) >= len(raw):
        return None
    return wrapped


def _decompress(codec: int, frame: bytes, size: int) -> bytes:
    if codec == RAW:
        return frame
    if codec == ZLIB:
        engine = zlib.decompressobj()
        try:
            out = engine.decompress(frame, size + 1)
        except zlib.error as exc:
            raise CodecError("compressed body is corrupt") from exc
        if not engine.eof or engine.unused_data or engine.unconsumed_tail:
            raise CodecError("compressed body has trailing or missing data")
        return out
    if codec == ZSTD:
        module = _zstd()
        if module is None:
            raise CodecError(
                "this file is zstd-compressed; install opentine[zstd] "
                "(Python 3.11-3.13) or use Python 3.14 to read it"
            )
        engine = module.ZstdDecompressor()
        try:
            out = engine.decompress(frame, size + 1)
        except module.ZstdError as exc:
            raise CodecError("compressed body is corrupt") from exc
        if not engine.eof or engine.unused_data:
            raise CodecError("compressed body has trailing or missing data")
        return out
    raise CodecError(f"unknown storage codec byte {codec}; a newer opentine wrote this")


def unwrap(data: bytes, *, limit: int) -> bytes:
    """The uncompressed bytes of a stored body, refusing anything over *limit*.

    Legacy (unwrapped) data comes back unchanged. A wrapped body must declare a
    length within *limit* and within ``MAX_RATIO`` of its frame, inflate to
    exactly that length, end where its frame ends, and not hold another wrapper.
    """
    if not is_wrapped(data):
        return data
    start = len(MAGIC)
    if len(data) <= start:
        raise CodecError("compressed header is truncated")
    codec = data[start]
    size, offset = _read_uvarint(data, start + 1)
    frame = data[offset:]
    if size > limit:
        raise CodecError("compressed body declares more bytes than the reader allows")
    if size > max(len(frame), 1) * MAX_RATIO:
        raise CodecError("compressed body exceeds the decompression ratio limit")
    out = _decompress(codec, frame, size)
    if len(out) != size:
        raise CodecError("compressed body does not match its declared length")
    if is_wrapped(out):
        raise CodecError("nested compression is not allowed")
    return out


def declared_size(data: bytes) -> int:
    """A stored body's uncompressed length without inflating it."""
    if not is_wrapped(data):
        return len(data)
    return _read_uvarint(data, len(MAGIC) + 1)[0]
