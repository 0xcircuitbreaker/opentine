"""A small, strict DER reader for the parts of CMS and RFC 3161 ``cryptography`` lacks.

:func:`read` decodes one TLV and returns a :class:`Node`; :meth:`Node.children`
splits a constructed value into its elements. Every malformed input raises
:class:`DerError` (a ``ValueError``): indefinite lengths, non-minimal lengths,
truncation, trailing bytes and high tag numbers beyond what CMS uses are all
refused. Nothing here recurses; nesting is walked one level at a time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

MAX_DER = 1024 * 1024

SEQUENCE, SET, INTEGER, OCTETS, OID, GENTIME, BOOLEAN = 0x30, 0x31, 0x02, 0x04, 0x06, 0x18, 0x01


class DerError(ValueError):
    """The bytes are not the DER this reader expects."""


@dataclass(frozen=True)
class Node:
    tag: int
    #: The whole TLV, header included (what a signature covers).
    raw: bytes
    #: The value bytes only.
    value: bytes

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> list[Node]:
        if not self.constructed:
            raise DerError(f"tag 0x{self.tag:02x} is not constructed")
        out, at = [], 0
        while at < len(self.value):
            node, at = _tlv(self.value, at)
            out.append(node)
        return out

    def expect(self, tag: int, what: str) -> Node:
        if self.tag != tag:
            raise DerError(f"{what}: expected tag 0x{tag:02x}, got 0x{self.tag:02x}")
        return self


def _tlv(data: bytes, at: int) -> tuple[Node, int]:
    if at + 2 > len(data):
        raise DerError("truncated DER header")
    tag = data[at]
    if tag & 0x1F == 0x1F:
        raise DerError("high-tag-number form is not used here")
    first = data[at + 1]
    head = at + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DerError("indefinite length is not DER")
    else:
        count = first & 0x7F
        if count > 4 or head + count > len(data):
            raise DerError("bad DER length")
        length = int.from_bytes(data[head : head + count], "big")
        if length < 0x80 or data[head] == 0:
            raise DerError("non-minimal DER length")
        head += count
    end = head + length
    if end > len(data):
        raise DerError("truncated DER value")
    return Node(tag, bytes(data[at:end]), bytes(data[head:end])), end


def read(data: bytes) -> Node:
    """Exactly one TLV filling *data*."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_DER:
        raise DerError("not DER bytes, or too large")
    node, end = _tlv(bytes(data), 0)
    if end != len(data):
        raise DerError("trailing bytes after DER value")
    return node


def as_int(node: Node) -> int:
    node.expect(INTEGER, "INTEGER")
    if not node.value:
        raise DerError("empty INTEGER")
    return int.from_bytes(node.value, "big", signed=True)


def as_oid(node: Node) -> str:
    node.expect(OID, "OBJECT IDENTIFIER")
    if not node.value or node.value[-1] & 0x80:
        raise DerError("malformed OBJECT IDENTIFIER")
    arcs, acc = [], 0
    for byte in node.value:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(acc)
            acc = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(a) for a in [first, arcs[0] - 40 * first, *arcs[1:]])


def as_gentime(node: Node) -> datetime:
    node.expect(GENTIME, "GeneralizedTime")
    text = node.value.decode("ascii", "replace")
    if len(text) < 15 or not text.endswith("Z") or not text[:14].isdigit():
        raise DerError("GeneralizedTime must be YYYYMMDDHHMMSS[.f]Z")
    stamp = datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    fraction = text[14:-1]
    if fraction:
        if not (fraction.startswith(".") and fraction[1:].isdigit() and len(fraction) <= 7):
            raise DerError("malformed GeneralizedTime fraction")
        stamp = stamp.replace(microsecond=int(fraction[1:].ljust(6, "0")))
    return stamp


def retag(node: Node, tag: int) -> bytes:
    """*node*'s TLV with its tag byte replaced (IMPLICIT [0] SET -> SET for signing)."""
    return bytes([tag]) + node.raw[1:]


__all__ = ["DerError", "Node", "as_gentime", "as_int", "as_oid", "read", "retag"]
