"""Reading a ``.tine`` file's bytes the way ``opentine._codec`` and ``_artifact_io`` do.

A ``TINEZ1`` wrapper is undone with the stdlib codecs only: raw, zlib and xz.
zstd (codec 2) is refused with :class:`ZstdRefused`, whose message says how to
get a copy this verifier can read. The JSON is parsed with the full reader's
refusals: NUL bytes, duplicate keys, non-finite numbers, excessive nesting.
"""

from __future__ import annotations

import json
import math
import re
import zlib
from typing import Any

from .. import kernel

MAGIC = b"TINEZ1\0"
RAW, ZLIB, ZSTD, XZ = 0, 1, 2, 4
#: The artifact byte cap of ``_artifact_io`` (256 MiB).
MAX_BYTES = 256 << 20
MAX_RATIO, READ_RATIO, READ_RATIO_BYTES = 1000, 100_000, 64 << 20
XZ_MEMLIMIT = 256 << 20
MAX_INTEGER_DIGITS = 4096
MIN_TOKENS, MAX_TOKENS, TOKEN_DENSITY = 200_000, 16_000_000, 4
SURROGATE_BYTES = re.compile(rb"\\u[dD][89a-fA-F]|\xed[\xa0-\xbf]")
REEXPORT = (
    "this file is zstd-compressed, which needs a native decoder this verifier does not "
    "carry; re-export the evidence with `tine evidence export --with-verifier`, which "
    "writes every run in the stdlib-readable archival form (xz or zlib) beside "
    "tine-verify.pyz"
)


class ZstdRefused(ValueError):
    """zstd-coded content: re-export it with ``tine evidence export --with-verifier``."""


def _uvarint(data: bytes, offset: int) -> tuple[int, int]:
    value = shift = 0
    for index in range(offset, min(len(data), offset + 10)):
        byte = data[index]
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return value, index + 1
    raise ValueError("compressed header is truncated")


def _decompress(codec: int, frame: bytes, size: int) -> bytes:
    if codec == RAW:
        return frame
    if codec == ZLIB:
        engine = zlib.decompressobj()
        out = engine.decompress(frame, size + 1)
        if not engine.eof or engine.unused_data:
            raise ValueError("compressed body has trailing or missing data")
        return out
    if codec == XZ:
        import lzma

        xz = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMLIMIT)
        out = xz.decompress(frame, size + 1)
        if not xz.eof or xz.unused_data:
            raise ValueError("compressed body has trailing or missing data")
        return out
    if codec == ZSTD:
        raise ZstdRefused(REEXPORT)
    raise ValueError(f"unknown storage codec {codec}")


def unwrap(data: bytes, limit: int = MAX_BYTES) -> bytes:
    """The uncompressed bytes of a stored body (``opentine._codec.unwrap``)."""
    if not data.startswith(MAGIC):
        return data
    if len(data) <= len(MAGIC):
        raise ValueError("compressed header is truncated")
    codec = data[len(MAGIC)]
    size, offset = _uvarint(data, len(MAGIC) + 1)
    frame = data[offset:]
    if codec == ZSTD:
        raise ZstdRefused(REEXPORT)
    if size > limit:
        raise ValueError("compressed body declares more bytes than the reader allows")
    ratio = READ_RATIO if size <= READ_RATIO_BYTES else MAX_RATIO
    if size > max(len(frame), 1) * ratio:
        raise ValueError("compressed body exceeds the decompression ratio limit")
    try:
        out = _decompress(codec, frame, size)
    except (zlib.error, EOFError, OSError) as exc:
        raise ValueError("compressed body is corrupt") from exc
    if len(out) != size:
        raise ValueError("compressed body does not match its declared length")
    if out.startswith(MAGIC):
        raise ValueError("nested compression is not allowed")
    return out


def is_zstd(data: bytes) -> bool:
    return data.startswith(MAGIC) and len(data) > len(MAGIC) and data[len(MAGIC)] == ZSTD


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate .tine object key: {key[:80]!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError(f"non-finite number in .tine artifact: {value}")


def _finite(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        _constant(value)
    return number


def parse(raw: bytes) -> Any:
    """Portable JSON with ``_artifact_io.parse_artifact_json``'s refusals."""
    if b"\0" in raw:
        raise ValueError(".tine artifacts must use UTF-8 JSON")
    try:
        budget = min(MAX_TOKENS, max(MIN_TOKENS, len(raw) // TOKEN_DENSITY))
        kernel.validate_json_shape(raw, max_tokens=budget)
    except kernel.KernelError as exc:
        raise ValueError(
            ".tine artifact nesting exceeds the parser limit or structure is excessive"
        ) from exc
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_finite,
            parse_int=_bounded_int,
        )
    except RecursionError as exc:
        raise ValueError(".tine artifact nesting exceeds the parser limit") from exc
    if SURROGATE_BYTES.search(raw):
        _refuse_surrogates(parsed)
    return parsed


def _bounded_int(value: str) -> int:
    if len(value.removeprefix("-")) > MAX_INTEGER_DIGITS:
        raise ValueError("integer in .tine artifact exceeds the parser limit")
    return int(value)


def _refuse_surrogates(value: Any) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError(".tine artifact holds a lone surrogate") from exc


def read(path: Any) -> Any:
    """The parsed artifact at *path* (a regular file within the byte cap)."""
    from pathlib import Path

    source = Path(path)
    if not source.is_file():
        raise ValueError(".tine artifact must be a regular file")
    with source.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(".tine artifact exceeds the size limit")
    return parse(unwrap(data))


__all__ = ["REEXPORT", "ZstdRefused", "is_zstd", "parse", "read", "unwrap"]
