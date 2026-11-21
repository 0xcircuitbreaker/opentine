"""Tokens of the policy language (0.74); the grammar is in :mod:`opentine._policy_lang`."""

from __future__ import annotations

import re
from typing import Any

MAX_SOURCE = 4096  # code points
MAX_SAFE = 2**53 - 1
KEYWORDS = {"true": True, "false": False, "null": None}
RESERVED = {"in", "as", "break", "const", "continue", "else", "for", "function", "if",
            "import", "let", "loop", "package", "namespace", "return", "var", "void",
            "while"}  # fmt: skip
_TOKEN = re.compile(
    r"(?P<ws>[ \t\r\n]+)"
    r"|(?P<num>(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_]*)"
    r"|(?P<op>&&|\|\||==|!=|<=|>=|[<>!()\[\],.\-])"
    r"|(?P<str>[\"'])"
)
_ESC = {"\\": "\\", '"': '"', "'": "'", "n": "\n", "r": "\r", "t": "\t"}
_HEX = re.compile(r"[0-9A-Fa-f]+")


class PolicyError(Exception):
    """An evaluation or parse error: ``code`` is stable, the message is not."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def number_ok(value: float | int) -> bool:
    """Finite, and an integral value lies within +-(2**53 - 1) (the JSON-safe range)."""
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return False
        return not value.is_integer() or abs(value) <= MAX_SAFE
    return abs(value) <= MAX_SAFE


def _string(src: str, pos: int, quote: str) -> tuple[str, int]:
    out: list[str] = []
    while True:
        if pos >= len(src) or src[pos] in "\r\n":
            raise PolicyError("policy.parse", "unterminated string")
        ch = src[pos]
        if ch == quote:
            return "".join(out), pos + 1
        if ch != "\\":
            out.append(ch)
            pos += 1
            continue
        esc = src[pos + 1 : pos + 2]
        if esc in _ESC:
            out.append(_ESC[esc])
            pos += 2
            continue
        width = {"u": 4, "U": 8}.get(esc)
        digits = src[pos + 2 : pos + 2 + width] if width else ""
        if not width or len(digits) != width or not _HEX.fullmatch(digits):
            raise PolicyError("policy.parse", "invalid escape in string")
        code = int(digits, 16)
        if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
            raise PolicyError("policy.parse", "escape is not a Unicode scalar value")
        out.append(chr(code))
        pos += 2 + width


def tokens(src: str) -> list[tuple[str, Any]]:
    if not isinstance(src, str) or len(src) > MAX_SOURCE:
        raise PolicyError("policy.parse", f"an expression is a string of at most {MAX_SOURCE}")
    out: list[tuple[str, Any]] = []
    pos = 0
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if not m:
            raise PolicyError("policy.parse", f"unexpected character at {pos}")
        kind = m.lastgroup
        if kind == "str":
            value, pos = _string(src, m.end(), m.group())
            out.append(("str", value))
            continue
        pos = m.end()
        if kind == "num":
            text = m.group()
            if any(c in text for c in ".eE"):
                value: Any = float(text)
            else:
                value = int(text)
            if not number_ok(value):
                raise PolicyError("policy.parse", "number literal out of range")
            nxt = src[pos : pos + 1]
            if nxt and re.fullmatch(r"[A-Za-z0-9_.]", nxt):
                raise PolicyError("policy.parse", "malformed number literal")
            out.append(("num", value))
        elif kind == "ident":
            out.append(("ident", m.group()))
        elif kind == "op":
            out.append(("op", m.group()))
    out.append(("end", None))
    return out


__all__ = ["KEYWORDS", "MAX_SAFE", "MAX_SOURCE", "RESERVED", "PolicyError", "number_ok",
           "tokens"]  # fmt: skip
