"""PuTTY private-key files (``.ppk``) for ``opentine.redaction``.

A PPK file carries no PEM ``-----BEGIN ... PRIVATE KEY-----`` marker, so the PEM
rule never saw one and ``cat ~/.ssh/id_rsa.ppk`` was recorded whole: the
``Private-Lines: N`` body that follows is a plaintext private key whenever the
file says ``Encryption: none``. Here the file, from its ``PuTTY-User-Key-File-N``
header through ``Private-MAC`` (or the last line that still belongs to it), is
replaced by the private-key label.

A file ends at its ``Private-MAC`` line, found within a bounded window after the
header (128 lines, 64 KiB, never past the next header or the unescaped quote that
ends a JSON string -- that last bound only when the file's line breaks are
JSON-escaped), whatever decorates each line: the Read tool's ``N→`` numbers,
``cat -n``, a diff's ``+``, a ``> `` quote or a YAML indent all used to stop a walk
that wanted each field at its line start, so only the header was redacted and the
plaintext ``Private-Lines`` body was written out. With no MAC in the window (a
truncated file), the lines are walked forward once -- the known header fields, and
exactly the ``Public-Lines`` / ``Private-Lines`` count of base64 lines after each,
each after its decoration and before trailing blanks -- so a prose line after a
truncated file is kept. Line breaks may be raw or JSON-escaped (``\\n``). Only in
the escaped form -- a file held in a JSON string -- does a quote end a line and the
file, which keeps the string's structure; with raw breaks a quote is ordinary text
(PuTTYgen allows one in ``Comment:``), so a quoted comment cannot cut the file
short and leave the ``Private-Lines`` body behind.
Every window ends at the next header, so the scan stays linear. A stdlib-only leaf.
"""

from __future__ import annotations

import re

from opentine._redact_edits import Edit

_LABEL = b"[REDACTED PRIVATE KEY]"
_HEADER = re.compile(rb"PuTTY-User-Key-File-\d{1,2}:[ \t]*[A-Za-z0-9@._-]{0,64}")
_FIELD = re.compile(
    rb"(Encryption|Comment|Public-Lines|Private-Lines|Private-MAC|Key-Derivation|Argon2-[A-Za-z]+)"
    rb":[ \t]*((?:[^\r\n\"\\]|\\[^nr\"\\])*)"
)
_DATA = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
_BREAK = re.compile(rb"\r?\n|\\r\\n|\\n")
#: A line ends at a break, a quote (the end of a JSON string), or the value's end.
_LINE_END = re.compile(rb"\r?\n|\\r\\n|\\n|\"|$")
#: The same three for a file with raw line breaks, where a quote is plain text.
_RAW_FIELD = re.compile(
    rb"(Encryption|Comment|Public-Lines|Private-Lines|Private-MAC|Key-Derivation|Argon2-[A-Za-z]+)"
    rb":[ \t]*([^\r\n]*)"
)
_RAW_BREAK = re.compile(rb"\r?\n")
_RAW_LINE_END = re.compile(rb"\r?\n|$")
_ESCAPED = (_FIELD, _BREAK, _LINE_END)
_RAW = (_RAW_FIELD, _RAW_BREAK, _RAW_LINE_END)
_MAX_LINES = 4096
#: Per-line decoration before a field or data line: a line number (``N→``, ``cat
#: -n``'s tab, ``nl``), a diff or quote marker, an indent.
_DECOR = re.compile(rb"[ \t]*(?:\d{1,9}(?:\xe2\x86\x92|\t|:| {1,2}))?[ \t]*(?:[+>|-][ \t]?)?[ \t]*")
_MAC = re.compile(rb"Private-MAC:")
_WINDOW_LINES = 128
_WINDOW_BYTES = 64 * 1024


def _line(
    pattern: re.Pattern[bytes], value: bytes, start: int, line_end: re.Pattern[bytes]
) -> tuple[re.Match[bytes], int] | None:
    """A decorated *pattern* line at *start*: the match and where its line ends."""
    start = _DECOR.match(value, start).end()
    match = pattern.match(value, start)
    if match is None or match.end() == start:
        return None
    tail = match.end()
    while tail < len(value) and value[tail] in (9, 32):
        tail += 1
    if not line_end.match(value, tail):
        return None
    return match, tail


def _escaped(value: bytes, cursor: int) -> bool:
    """Whether the header ending at *cursor* is followed by a JSON-escaped break."""
    while cursor < len(value) and value[cursor] in (9, 32):
        cursor += 1
    return value.startswith(b"\\", cursor)


def _string_end(value: bytes, start: int, limit: int) -> int:
    """The first quote in ``value[start:limit]`` that a backslash does not escape."""
    index = value.find(b'"', start, limit)
    while index >= 0:
        run = index
        while run > start and value[run - 1] == 92:
            run -= 1
        if (index - run) % 2 == 0:
            return index
        index = value.find(b'"', index + 1, limit)
    return limit


def _mac_end(value: bytes, cursor: int, limit: int, escaped: bool) -> int | None:
    """End of the ``Private-MAC`` line within the window after a header, if any."""
    limit = min(limit, cursor + _WINDOW_BYTES)
    if escaped:
        limit = _string_end(value, cursor, limit)
    breaks = _BREAK if escaped else _RAW_BREAK
    for _ in range(_WINDOW_LINES + 1):
        brk = breaks.search(value, cursor, limit)
        line_end = brk.start() if brk else limit
        if _MAC.search(value, cursor, line_end):
            return line_end
        if brk is None:
            return None
        cursor = brk.end()
    return None


def _walk_end(value: bytes, cursor: int, escaped: bool) -> int:
    """Where a truncated PPK file (no MAC in the window) ends, walked by its counts."""
    fields, breaks, line_end = _ESCAPED if escaped else _RAW
    last = cursor
    pending = 0  # base64 lines still owed to the last *-Lines field
    while brk := breaks.match(value, cursor):
        start = brk.end()
        if pending:
            data = _line(_DATA, value, start, line_end)
            if data is None:
                return last
            pending -= 1
            last = cursor = data[1]
            continue
        found = _line(fields, value, start, line_end)
        if found is None:
            return last
        field, last = found
        cursor = last
        name = field.group(1)
        if name == b"Private-MAC":
            return last
        if name.endswith(b"-Lines") and field.group(2).strip().isdigit():
            pending = min(int(field.group(2).strip()), _MAX_LINES)
    return last


def _file_end(value: bytes, cursor: int, limit: int) -> int:
    """Where the PPK file whose header ends at *cursor* ends (before *limit*)."""
    escaped = _escaped(value, cursor)
    mac = _mac_end(value, cursor, limit, escaped)
    return mac if mac is not None else min(_walk_end(value, cursor, escaped), limit)


def ppk_edits(value: bytes) -> list[Edit]:
    """Each PuTTY key file in *value* becomes the private-key label."""
    edits: list[Edit] = []
    header = _HEADER.search(value)
    while header is not None:
        following = _HEADER.search(value, header.end())
        limit = following.start() if following else len(value)
        end = _file_end(value, header.end(), limit)
        edits.append((header.start(), end, _LABEL))
        while following is not None and following.start() < end:
            following = _HEADER.search(value, following.end())
        header = following
    return edits


__all__ = ["ppk_edits"]
