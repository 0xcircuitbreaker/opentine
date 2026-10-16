"""Quoted credential fields: ``"password": "x"``, and the escaped ``\\"password\\":\\"x\\"``.

A stdlib-only leaf. The escaped spelling is how a JSON document appears inside
other text -- ``curl -d "{\\"password\\":\\"x\\"}"``, an ``echo`` line, a logger that
prints a payload with its quotes escaped -- and inside the raw bytes of a JSON
string. Its name is followed by ``\\"`` rather than ``"``, so the plain field rule
and the assignment rule both missed it and the value was written out.

Which names count is decided by ``_redact_names.secret_name`` -- the predicate the
record walk applies to dict keys -- so ``"MYSQL_PWD": "…"`` or ``"app.db.pwd": "…"``
is redacted as text exactly when the same object would be redacted as a dict.
"""

from __future__ import annotations

import re
from collections.abc import Callable

Edit = tuple[int, int, bytes]
_BACKSLASH = 92
#: ``"NAME": "`` or ``\\"NAME\\": \\"`` (the same escaping on all three quotes), for
#: any field name; the caller's predicate decides whether the name is secret. The
#: name is unbounded, as 0.9.2's was: a match starts only at a quote, so each name
#: run is scanned once, and the predicate reads only the name's last ``NAME_TAIL``
#: bytes (``…_password`` is secret however long its prefix).
FIELD = re.compile(rb"((\\?)[\"']([A-Za-z0-9_.@$-]+)\2[\"']\s*:\s*)(\2[\"'])")
NAME_TAIL = 256
_DIGITS = re.compile(rb"[0-9]+")


def value_end(value: bytes, start: int, quote: int, escaped: bool) -> tuple[int, int]:
    """Where the value ends, and where scanning resumes after it."""
    end = start
    while end < len(value) and value[end] not in (10, 13):
        byte = value[end]
        if byte == _BACKSLASH:
            run = end
            while run < len(value) and value[run] == _BACKSLASH:
                run += 1
            if escaped and run - end == 1 and run < len(value) and value[run] == quote:
                return end, run + 1  # ``\\"`` closes an escaped value
            # An odd run escapes the byte after it (``\\\\\\"`` is a literal quote).
            end = min(run + (run - end) % 2, len(value))
            continue
        if byte == quote:
            # Plain: the closing quote. Escaped: an unescaped quote is the end of
            # the string that holds the text; stop before it so JSON stays JSON.
            return end, end + (0 if escaped else 1)
        end += 1
    return end, end


def _counter(name: bytes) -> bool:
    """A plural ``*tokens`` name (``input_tokens``): a digit-only value is a usage count."""
    return name.lower().endswith(b"tokens")


def quoted_field_edits(
    pattern: re.Pattern[bytes], value: bytes, secret: Callable[[bytes], bool]
) -> list[Edit]:
    edits: list[Edit] = []
    cursor = 0
    while match := pattern.search(value, cursor):
        # Resume at the value's opening quote, not past the value: that quote may
        # open the next field's name (``"a": "password": "v"``). Each byte is
        # scanned at most twice, and the next value starts past this edit.
        cursor = match.start(4)
        if not secret(match.group(3)) or (edits and match.end() < edits[-1][1]):
            continue  # an edit never overlaps the one before it
        escaped = bool(match.group(2))
        end, _ = value_end(value, match.end(), match.group(4)[-1], escaped)
        if not (_counter(match.group(3)) and _DIGITS.fullmatch(value, match.end(), end)):
            edits.append((match.end(), end, b"[REDACTED]"))
    return edits
