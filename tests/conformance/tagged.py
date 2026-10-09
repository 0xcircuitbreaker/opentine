"""The four-tag value encoding shared by the vectors and the neutral runner.

Plain JSON cannot distinguish an integer from a double, cannot spell an integer
beyond 2**53-1, and cannot spell NaN or Infinity at all -- and all three
distinctions are load-bearing in a format whose two canonicalizers render them
differently. ``input.value`` therefore uses plain JSON with exactly four
escapes, each recognised only on a **single-key object whose sole key is
exactly** ``$i``, ``$f``, ``$u`` or ``$obj``:

* ``{"$i": "<decimal digits, optional leading ->"}``  -- an integer of any size
* ``{"$f": "<round-tripping literal>"}``              -- an IEEE-754 double,
  or exactly one of ``"nan"``, ``"inf"``, ``"-inf"``
* ``{"$u": ["d800", ...]}``                           -- a string given as its
  UTF-16 code units, four lowercase hex digits each
* ``{"$obj": {...}}`` or ``{"$obj": [[key, value], ...]}`` -- a genuine object:
  the mapping form escapes a single ``$``-prefixed key, the pair-list form
  carries keys that themselves need a tagged spelling

Strings, booleans, ``null``, arrays and multi-key objects are literal. A bare
JSON number never appears inside ``input.value``; ``test_conformance_drift``
asserts that, so an implementer never has to guess an untagged number's type.

``$u`` exists so the vector *files* stay parseable by every language. A lone
UTF-16 surrogate has no UTF-8 spelling and no valid JSON escape a strict parser
will accept, yet SPEC 0.1 and SPEC 0.2 rule 1 both turn on one; spelled as code
units, the file is ordinary JSON and only an adapter that opts into the
``wtf8`` capability has to materialize the string at all.
"""

from __future__ import annotations

import math
from typing import Any

TAGS = ("$i", "$f", "$u", "$obj")
SPECIAL_FLOATS = {"nan": math.nan, "inf": math.inf, "-inf": -math.inf}


def _float_literal(value: float) -> str:
    if math.isnan(value):
        return "nan"
    if math.isinf(value):
        return "inf" if value > 0 else "-inf"
    return repr(value)


def needs_code_units(text: str) -> bool:
    """Whether a string holds a code point no strict JSON parser will hand back."""
    return any(0xD800 <= ord(char) <= 0xDFFF for char in text)


def _code_units(text: str) -> list[str]:
    units: list[str] = []
    for char in text:
        point = ord(char)
        if point > 0xFFFF:
            offset = point - 0x10000
            units.append(f"{0xD800 + (offset >> 10):04x}")
            units.append(f"{0xDC00 + (offset & 0x3FF):04x}")
        else:
            units.append(f"{point:04x}")
    return units


def _from_code_units(units: list[str]) -> str:
    return "".join(chr(int(unit, 16)) for unit in units)


def encode(value: Any) -> Any:
    """Python value -> its tagged JSON spelling."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        return {"$u": _code_units(value)} if needs_code_units(value) else value
    if isinstance(value, int):
        return {"$i": str(value)}
    if isinstance(value, float):
        return {"$f": _float_literal(value)}
    # Recursion below uses plain loops, never comprehensions: on Python 3.11 a
    # comprehension is its own frame, so each nesting level cost two frames and
    # the 512-deep vectors overflowed the default recursion limit (3.12+ inlines
    # comprehensions, PEP 709, which is why only 3.11 failed).
    if isinstance(value, (list, tuple)):
        items = []
        for item in value:
            items.append(encode(item))
        return items
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("a non-string object key cannot be spelled in a tagged tree")
        if any(needs_code_units(key) for key in value):
            pairs = []
            for key, item in value.items():
                pairs.append([encode(key), encode(item)])
            return {"$obj": pairs}
        body = {}
        for key, item in value.items():
            body[key] = encode(item)
        if len(body) == 1 and next(iter(body)).startswith("$"):
            return {"$obj": body}
        return body
    raise TypeError(f"unsupported tagged value: {type(value).__name__}")


def decode(node: Any) -> Any:
    """Tagged JSON spelling -> the Python value it denotes."""
    if isinstance(node, list):
        items = []
        for item in node:
            items.append(decode(item))
        return items
    if not isinstance(node, dict):
        return node
    if len(node) == 1:
        tag, payload = next(iter(node.items()))
        if tag == "$i":
            return int(payload)
        if tag == "$f":
            return SPECIAL_FLOATS[payload] if payload in SPECIAL_FLOATS else float(payload)
        if tag == "$u":
            return _from_code_units(payload)
        if tag == "$obj":
            decoded = {}
            for key, item in payload if isinstance(payload, list) else payload.items():
                decoded[decode(key) if isinstance(payload, list) else key] = decode(item)
            return decoded
    body = {}
    for key, item in node.items():
        body[key] = decode(item)
    return body


def contains_bare_number(node: Any) -> bool:
    """Whether any bare JSON number survives in a tagged tree (a drift gate)."""
    if isinstance(node, bool) or node is None or isinstance(node, str):
        return False
    if isinstance(node, (int, float)):
        return True
    if isinstance(node, list):
        return any(contains_bare_number(item) for item in node)
    if isinstance(node, dict):
        if len(node) == 1 and next(iter(node)) in {"$i", "$f"}:
            return not isinstance(next(iter(node.values())), str)
        return any(contains_bare_number(item) for item in node.values())
    return True
