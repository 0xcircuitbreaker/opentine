"""Hash-Elision Coding (HEC): the ``HEC1`` body of ``TINEPACK6`` (0.81).

A pack is an ordered table of content-addressed objects. Each body is carried
as a template: literal bytes with holes the decoder recomputes -- the id of an
earlier object (a link), a value derived from the object itself, or a copy of
an earlier literal unit. The decoder rebuilds every body and recomputes every
id; it never reads an id from the pack, so decoding is verification.

This package is the pure-Python engine with only the ``opentine-1`` grammar.
Normative decode rules and reason codes: ``docs/SPEC.md``, "TINEPACK6".
"""

from opentine._hec import opentine1
from opentine._hec._core import (
    ANY,
    DEFAULT_LIMITS,
    REASON_CODES,
    Closure,
    Decoded,
    HecError,
    Limits,
)
from opentine._hec._decode import decode
from opentine._hec._encode import dependency_order, encode
from opentine._hec.opentine1 import OPENTINE

__all__ = [
    "ANY",
    "DEFAULT_LIMITS",
    "OPENTINE",
    "REASON_CODES",
    "Closure",
    "Decoded",
    "HecError",
    "Limits",
    "decode",
    "dependency_order",
    "encode",
    "opentine1",
]
