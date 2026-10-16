"""A linear, hand-written JSON tokenizer for redaction: tokens with byte offsets.

``_redact_json`` splices whole-string replacements back into the original bytes,
so it needs where every string, number and literal starts and ends -- which
``json.loads`` does not give -- and a structural fingerprint to tell a scan that
kept a document's shape from one that ate a quote or a separator. No regular
expression runs over the document here: a string ends at the first quote with an
even run of backslashes before it (found with ``bytes.find``) and is validated by
``json.loads`` on its own token, and the grammar is a flat state machine with an
explicit stack, so time is linear and any depth is fine.
"""

from __future__ import annotations

import json
import re

#: ``(kind, start, end, owner)``: kind is one of ``{}[]:,``, ``s`` (string), ``n``
#: (number or literal) or ``|`` (the end of one JSON Lines document); owner is the
#: index of the object a member-name string belongs to, else -1.
Token = tuple[str, int, int, int]
_WS = frozenset(b" \t\r\n")
_NUMBER_BYTES = frozenset(b"+-0123456789.eE")
_NUMBER = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
#: ``NaN``/``Infinity`` are not JSON, but ``json.dumps`` writes them by default and
#: ``json.loads`` reads them, so a document carrying one is still treated as one.
_LITERALS = (b"true", b"false", b"null", b"NaN", b"Infinity", b"-Infinity")


def _string_end(data: bytes, start: int) -> int:
    """Offset just past the string opening at *start*, or -1 if it is not one."""
    cursor = start + 1
    while True:
        quote = data.find(b'"', cursor)
        if quote < 0:
            return -1
        slash = quote - 1
        while slash > start and data[slash] == 92:
            slash -= 1
        if (quote - 1 - slash) % 2 == 0:
            break
        cursor = quote + 1
    try:
        json.loads(data[start : quote + 1].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return -1
    return quote + 1


def _scalar(data: bytes, i: int) -> int:
    """Offset just past the number or literal at *i*, or -1."""
    for literal in _LITERALS:
        if data.startswith(literal, i):
            return i + len(literal)
    end = i
    while end < len(data) and data[end] in _NUMBER_BYTES:
        end += 1
    return end if end > i and _NUMBER.fullmatch(data, i, end) else -1


def tokenize(data: bytes, base: int = 0, owners: int = 0) -> tuple[list[Token], int] | None:  # noqa: C901
    """*data* as one JSON document: its tokens (offsets + *base*) and object count."""
    tokens: list[Token] = []
    stack: list[int] = []  # object index, or -1 for an array
    i, n, expect = 0, len(data), "value"
    while True:
        while i < n and data[i] in _WS:
            i += 1
        if expect == "after":
            if not stack:
                return (tokens, owners) if i == n else None
            if i == n:
                return None
            char, top = chr(data[i]), stack[-1]
            if char == ",":
                expect = "key" if top >= 0 else "value"
            elif char == ("}" if top >= 0 else "]"):
                stack.pop()
            else:
                return None
            tokens.append((char, base + i, base + i + 1, -1))
            i += 1
            continue
        if i == n:
            return None
        char = chr(data[i])
        if expect in ("key", "key_or_close"):
            if char == "}" and expect == "key_or_close":
                stack.pop()
                tokens.append(("}", base + i, base + i + 1, -1))
                i, expect = i + 1, "after"
                continue
            end = _string_end(data, i) if char == '"' else -1
            if end < 0:
                return None
            tokens.append(("s", base + i, base + end, stack[-1]))
            i = end
            while i < n and data[i] in _WS:
                i += 1
            if i == n or data[i] != 58:  # ":"
                return None
            tokens.append((":", base + i, base + i + 1, -1))
            i, expect = i + 1, "value"
            continue
        if char == "]" and expect == "value_or_close":
            stack.pop()
            tokens.append(("]", base + i, base + i + 1, -1))
            i, expect = i + 1, "after"
            continue
        if char in "{[":
            tokens.append((char, base + i, base + i + 1, -1))
            stack.append(owners if char == "{" else -1)
            owners += char == "{"
            i, expect = i + 1, ("key_or_close" if char == "{" else "value_or_close")
            continue
        end = _string_end(data, i) if char == '"' else _scalar(data, i)
        if end < 0:
            return None
        tokens.append(("s" if char == '"' else "n", base + i, base + end, -1))
        i, expect = end, "after"


def parse_blob(data: bytes) -> list[Token] | None:
    """Tokens of *data* as one JSON document, or as JSON Lines, else None."""
    whole = tokenize(data)
    if whole is not None:
        return whole[0]
    if b"\n" not in data:
        return None
    tokens: list[Token] = []
    offset = owners = 0
    for line in data.split(b"\n"):
        if line.strip():
            parsed = tokenize(line, offset, owners)
            if parsed is None:
                return None
            tokens.extend(parsed[0])
            owners = parsed[1]
            tokens.append(("|", offset + len(line), offset + len(line), -1))
        offset += len(line) + 1
    return tokens or None


def decoded_offsets(token: bytes) -> list[int] | None:
    """For a JSON string token, the decoded UTF-8 offset at each of its byte offsets.

    An offset inside an escape maps to where that escape's text starts, so a span
    ``[low, high)`` of the token covers ``text[map[low] : map[high]]`` once *high*
    is moved past the escape it cuts (an offset whose map changes at the next byte).
    None when the walk does not reproduce ``json.loads`` exactly.
    """
    offsets = [0] * (len(token) + 1)
    i, size, end = 1, 0, len(token) - 1
    while i < end:
        width, text = 1, 1
        if token[i] == 92:  # backslash
            width = 2
            if token[i + 1 : i + 2] == b"u":
                point = int(token[i + 2 : i + 6], 16)
                width, text = 6, (1 if point < 0x80 else 2 if point < 0x800 else 3)
                low = token[i + 8 : i + 12] if token[i + 6 : i + 8] == b"\\u" else b""
                if 0xD800 <= point < 0xDC00 and low and 0xDC00 <= int(low, 16) < 0xE000:
                    width, text = 12, 4
        for j in range(i, min(i + width, end)):
            offsets[j] = size
        size, i = size + text, i + width
    offsets[end] = offsets[end + 1] = size
    try:
        expected = len(json.loads(token.decode("utf-8")).encode("utf-8", "surrogatepass"))
    except (ValueError, UnicodeError):
        return None
    return offsets if expected == size else None


def shape(tokens: list[Token]) -> list[tuple[str, bool]]:
    """The structural fingerprint: token kinds, member names marked."""
    return [(kind, owner >= 0) for kind, _, _, owner in tokens]


__all__ = ["Token", "decoded_offsets", "parse_blob", "shape", "tokenize"]
