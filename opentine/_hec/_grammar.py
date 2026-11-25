"""Building blocks for HEC grammars.

A grammar has a ``name`` (written into the pack, checked by the decoder), a
tuple of ``fields`` (wire code = position), ``type_info(desc)`` (a strict
parser of a type descriptor, raising ``HecError("grammar")``) and
``object_id(type, body)``. A type's scanner (encoder only) yields candidates
``(start, end, field_index, key, alt)`` in increasing position; the encoder
keeps one only when the decoder's rendering equals the span byte for byte.
"""

from __future__ import annotations

import re
from collections.abc import Callable

#: Pseudo field index: "this span is a literal unit worth deduplicating".
UNIT = -1


def as_hex(b: bytes) -> bytes:
    return b.hex().encode()


class Type:
    """One object type: literal stream ``lit``, encoder ``scan``, allowed field ``holes``."""

    __slots__ = ("desc", "extra", "holes", "lit", "name", "scan")

    def __init__(self, desc: bytes, name: bytes, lit: int = 0, scan=None, extra=None, holes=None):
        self.desc = desc
        self.name = name
        self.lit = lit
        self.scan = scan or (lambda body: ())
        self.extra = extra
        self.holes = holes


class Link:
    """A digest field whose value is the identifier of an earlier object."""

    kind = "link"

    def __init__(self, name: str, mode: str = "abs", form=None, top: bool = False) -> None:
        self.name = name
        self.mode = mode
        self.form = form
        self.top = top

    def render(self, obj, ctx) -> bytes:
        return self.form(obj.id)


class Opaque:
    """A digest that cannot be derived: ``size`` raw bytes in the opaque stream."""

    kind = "opaque"

    def __init__(self, name: str, size: int, form=None, parse=None) -> None:
        self.name = name
        self.size = size
        self.render: Callable[[bytes], bytes] = form or (lambda raw: raw)
        self.parse = parse or (lambda span: span if len(span) == size else None)


class SelfDerived:
    """A value computed from the object being rebuilt (at most one per object)."""

    kind = "self"

    def __init__(self, name: str, fn) -> None:
        self.name = name
        self.render = fn


def hex_parse(size: int):
    pat = re.compile(rb"[0-9a-f]{%d}" % (2 * size))
    return lambda span: bytes.fromhex(span.decode()) if pat.fullmatch(span) else None
