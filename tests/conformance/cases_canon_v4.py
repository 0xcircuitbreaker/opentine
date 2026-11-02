"""SPEC Part 9: format v4's canonical form is RFC 8785 (JCS).

v4 canonical bytes ARE ``kernel.canonical_json`` -- the SPEC 0.2 function -- so
these vectors run through the ``canon.v3`` op: a second op would invite a second
implementation. What they add is the RFC 8785 / cyberphone IEEE-754 corpus
(shortest round-trip with the tie cases), UTF-16 key order past the BMP, and
JCS string escaping, so an implementer can check a stock JCS library against
the v4 form. ``tests/test_format_v4_0_26.py`` pins the hand-typed JCS answers.
"""

from __future__ import annotations

import math
import struct

from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V

READER = "reader"

#: IEEE-754 doubles from RFC 8785 Appendix B and the cyberphone es6testfile.
IEEE_BITS = (
    "0000000000000000", "8000000000000000", "0000000000000001", "8000000000000001",
    "7fefffffffffffff", "ffefffffffffffff", "4340000000000000", "c340000000000000",
    "4430000000000000", "44b52d02c7e14af5", "44b52d02c7e14af6", "44b52d02c7e14af7",
    "444b1ae4d6e2ef4e", "444b1ae4d6e2ef4f", "444b1ae4d6e2ef50", "3eb0c6f7a0b5ed8c",
    "3eb0c6f7a0b5ed8d", "41b3de4355555553", "41b3de4355555554", "41b3de4355555555",
    "41b3de4355555556", "41b3de4355555557", "becbf647612f3696", "43143ff3c1cb0959",
)  # fmt: skip


def _double(bits: str) -> float:
    return struct.unpack(">d", bytes.fromhex(bits))[0]


def _v4(name: str, expect: str, intent: str, value, **extra) -> Case:
    return Case(
        id=f"canon.v4.{name}",
        section="9.2",
        checklist=(2,),
        op="canon.v3",
        profile=READER,
        expect=expect,
        intent=intent,
        input=V(value),
        **extra,
    )


CANON_V4 = Family(
    "09-canon-v4.json",
    "9.2",
    "canon-v4",
    (
        *(
            _v4(
                f"ieee.{bits}",
                ACCEPT,
                f"RFC 8785 3.2.2.3: the IEEE-754 double 0x{bits} serializes as ECMAScript "
                "Number.prototype.toString does, ties included",
                {"n": _double(bits)},
            )
            for bits in IEEE_BITS
        ),
        _v4(
            "key.order-utf16",
            ACCEPT,
            "RFC 8785 3.2.3: keys sort by UTF-16 code units, so U+1F600 precedes U+FB33",
            {
                "€": "Euro Sign",
                "\r": "Carriage Return",
                "דּ": "Hebrew Letter Dalet With Dagesh",
                "1": "One",
                "\U0001f600": "Emoji: Grinning Face",
                "\u0080": "Control",
                "ö": "Latin Small Letter O With Diaeresis",
            },
        ),
        _v4(
            "string.rfc-example",
            ACCEPT,
            'RFC 8785 3.2.2.2: only " and \\ and controls are escaped; / and U+20AC are literal',
            {"s": '€$\u000f\nA\'B"\\\\"/'},
        ),
        _v4(
            "string.controls",
            ACCEPT,
            "the five short escapes, \\u00XX in lowercase hex, and DEL emitted literally",
            {"s": "\b\t\n\f\r\x1f\x7f"},
        ),
        _v4(
            "string.line-separators",
            ACCEPT,
            "U+2028 and U+2029 are emitted literally, never escaped",
            {"s": "  "},
        ),
        _v4(
            "float.nan",
            REJECT,
            "RFC 8785 3.2.2.3: NaN (0x7fffffffffffffff) has no JCS spelling",
            {"n": math.nan},
            reason="canon.non-finite",
        ),
        _v4(
            "float.infinity",
            REJECT,
            "RFC 8785 3.2.2.3: Infinity (0x7ff0000000000000) has no JCS spelling",
            {"n": math.inf},
            reason="canon.non-finite",
        ),
        _v4(
            "integer.at-2-53",
            REJECT,
            "an integer of 2**53 is refused, not rounded: I-JSON interoperability bound",
            {"n": 9007199254740992},
            reason="canon.integer-overflow",
            repair_temptation="emit it as the double 9007199254740992, which loses the type",
        ),
        _v4(
            "integer.2-64",
            REJECT,
            "a 64-bit identifier is refused, never rounded to the nearest double",
            {"n": 18446744073709551616},
            reason="canon.integer-overflow",
            repair_temptation="round to 18446744073709552000, a different identifier",
        ),
        _v4(
            "surrogate.value",
            REJECT,
            "RFC 8785 requires well-formed UTF-8, in which a lone surrogate has no spelling",
            {"s": "\ud800"},
            reason="canon.unencodable-text",
            requires=("wtf8",),
        ),
        _v4(
            "surrogate.key",
            REJECT,
            "the same rule over an object key",
            {"\udc00": 1},
            reason="canon.unencodable-text",
            requires=("wtf8",),
        ),
    ),
)

FAMILIES = (CANON_V4,)
