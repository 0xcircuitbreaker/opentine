"""A small, bounded CBOR (RFC 8949) codec for COSE (0.44, SCITT; stdlib only).

Decoding accepts definite-length items only, at most ``MAX_DEPTH`` deep and
``MAX_ITEMS`` items, and refuses trailing bytes, non-minimal-free surprises like
indefinite lengths, and lengths past the input. Tags decode to :class:`Tag`;
``false``/``true``/``null`` to Python values; floats to ``float``. Map keys
must be integers or text (as COSE uses them). Encoding covers what COSE
signing structures need: int, bytes, str, list, dict, bool, None, Tag, with
shortest-form heads (RFC 8949 §4.2.1 preferred serialization).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

MAX_DEPTH = 16
MAX_ITEMS = 100_000
MAX_BYTES = 1 << 24


class CBORError(ValueError):
    """The bytes are not CBOR this codec accepts."""


@dataclass(frozen=True)
class Tag:
    tag: int
    value: Any


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos, self.items = data, 0, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise CBORError("CBOR item runs past the input")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def head(self) -> tuple[int, int, int]:
        first = self.take(1)[0]
        major, info = first >> 5, first & 0x1F
        if info < 24:
            return major, info, info
        if info > 27:
            raise CBORError("indefinite-length or reserved CBOR item")
        return major, info, int.from_bytes(self.take(1 << (info - 24)), "big")

    def item(self, depth: int = 0) -> Any:
        if depth > MAX_DEPTH:
            raise CBORError("CBOR nests too deeply")
        self.items += 1
        if self.items > MAX_ITEMS:
            raise CBORError("CBOR has too many items")
        major, info, value = self.head()
        if major == 0:
            return value
        if major == 1:
            return -1 - value
        if major == 2:
            return self.take(value)
        if major == 3:
            try:
                return self.take(value).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CBORError("CBOR text is not UTF-8") from exc
        if major == 4:
            if value > len(self.data):
                raise CBORError("CBOR array is longer than the input")
            return [self.item(depth + 1) for _ in range(value)]
        if major == 5:
            if value > len(self.data):
                raise CBORError("CBOR map is longer than the input")
            out: dict[Any, Any] = {}
            for _ in range(value):
                key = self.item(depth + 1)
                if not isinstance(key, int | str) or isinstance(key, bool) or key in out:
                    raise CBORError("CBOR map key is not a unique int or text")
                out[key] = self.item(depth + 1)
            return out
        if major == 6:
            return Tag(value, self.item(depth + 1))
        return self._simple(info, value)

    def _simple(self, info: int, value: int) -> Any:
        if info < 24 or info == 24:
            simple = {20: False, 21: True, 22: None}
            if value not in simple:
                raise CBORError(f"unsupported CBOR simple value {value}")
            return simple[value]
        size = 1 << (info - 24)
        raw = value.to_bytes(size, "big")
        return struct.unpack({2: ">e", 4: ">f", 8: ">d"}[size], raw)[0]


def loads(data: bytes) -> Any:
    if not isinstance(data, bytes | bytearray) or len(data) > MAX_BYTES:
        raise CBORError("CBOR input is not bytes or is too large")
    reader = _Reader(bytes(data))
    value = reader.item()
    if reader.pos != len(reader.data):
        raise CBORError("trailing bytes after the CBOR item")
    return value


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([major << 5 | value])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (8 * size):
            return bytes([major << 5 | info]) + value.to_bytes(size, "big")
    raise CBORError("integer is too large for CBOR")


def dumps(value: Any) -> bytes:
    if value is False or value is True or value is None:
        return bytes([0xF4 + (1 if value is True else 0 if value is False else 2)])
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes | bytearray):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, list | tuple):
        return _head(4, len(value)) + b"".join(dumps(v) for v in value)
    if isinstance(value, dict):
        return _head(5, len(value)) + b"".join(dumps(k) + dumps(v) for k, v in value.items())
    if isinstance(value, Tag):
        return _head(6, value.tag) + dumps(value.value)
    raise CBORError(f"cannot encode {type(value).__name__} as CBOR")
