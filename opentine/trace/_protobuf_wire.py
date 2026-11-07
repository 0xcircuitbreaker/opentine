"""A stdlib-only protobuf wire-format reader, bounded for untrusted input.

OpenTine has no protobuf dependency. OTLP/HTTP protobuf only needs the four
wire types proto3 uses (varint, fixed64, length-delimited, fixed32), so this
module splits a message into ``(field, wire_type, value)`` triples and leaves
the meaning of each field to the caller (:mod:`opentine.trace._otlp_proto`).

Every malformed input -- a truncated varint, a length past the end, a group
wire type, a field number of 0, too many fields or too deep a nesting -- is a
:class:`WireError` (a ``ValueError``), never an ``IndexError`` or a hang.
"""

from __future__ import annotations

import struct

#: Bytes one decoded message may hold, nesting depth, and fields across a decode.
MAX_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 32
MAX_FIELDS = 2_000_000
VARINT, FIXED64, LEN, FIXED32 = 0, 1, 2, 5


class WireError(ValueError):
    """The bytes are not a well-formed protobuf message within the caps."""


class Budget:
    """Fields left across one whole decode, shared by every nested message."""

    def __init__(self, fields: int = MAX_FIELDS) -> None:
        self.fields = fields

    def take(self) -> None:
        self.fields -= 1
        if self.fields < 0:
            raise WireError(f"message carries more than {MAX_FIELDS} fields")


def varint(data: bytes, offset: int) -> tuple[int, int]:
    """``(value, next_offset)`` of the varint at *offset*; at most 10 bytes."""
    result = shift = 0
    for index in range(offset, min(offset + 10, len(data))):
        byte = data[index]
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if result >> 64:
                raise WireError("varint overflows 64 bits")
            return result, index + 1
        shift += 7
    raise WireError("truncated or overlong varint")


def fields(data: bytes, budget: Budget | None = None) -> list[tuple[int, int, int | bytes]]:
    """Every field of one message, in wire order."""
    if len(data) > MAX_BYTES:
        raise WireError(f"message exceeds {MAX_BYTES} bytes")
    budget = budget or Budget()
    out: list[tuple[int, int, int | bytes]] = []
    offset, end = 0, len(data)
    while offset < end:
        key, offset = varint(data, offset)
        number, wire = key >> 3, key & 7
        if number == 0 or number > 0x1FFFFFFF:
            raise WireError(f"invalid field number {number}")
        budget.take()
        value: int | bytes
        if wire == VARINT:
            value, offset = varint(data, offset)
        elif wire in (FIXED64, FIXED32):
            size = 8 if wire == FIXED64 else 4
            if offset + size > end:
                raise WireError("truncated fixed-width field")
            value = int.from_bytes(data[offset : offset + size], "little")
            offset += size
        elif wire == LEN:
            size, offset = varint(data, offset)
            if size > end - offset:
                raise WireError("length-delimited field runs past the message")
            value = data[offset : offset + size]
            offset += size
        else:
            raise WireError(f"unsupported wire type {wire}")
        out.append((number, wire, value))
    return out


def signed64(value: int) -> int:
    """A proto ``int64`` varint as a Python int (two's complement)."""
    return value - (1 << 64) if value >> 63 else value


def double(value: int) -> float:
    return float(struct.unpack("<d", value.to_bytes(8, "little"))[0])


__all__ = ["MAX_DEPTH", "Budget", "WireError", "double", "fields", "signed64", "varint"]
