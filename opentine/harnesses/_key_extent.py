"""How far a private key reaches, inside one string and across delta events.

A ``BEGIN`` marker with no ``END`` used to mask the rest of its string, and the
block it opened then masked every later string at the same path -- whole events
included -- until some string there held ``END``. One ``printf`` of the marker,
or a fetched page that shows one, erased every later tool command, tool result
and model message from the record (final pass 7, #6). Masking now reaches only
as far as key material does: the marker, then the base64 body (and an encrypted
block's ``Proc-Type``/``DEK-Info`` headers) that follows it, stopping at the
first line of prose -- the record scrubber's own rule. A block carries into the
next event only from a streamed *delta* whose body ran to the end of its string,
only into another delta of the same stream, and only while that delta is still
key-shaped.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from opentine.harnesses._key_decor import HEADER, key_body
from opentine.harnesses._key_patterns import BEGIN, END, PLACEHOLDER

#: What ``str.splitlines`` breaks on; lines are walked lazily from an offset,
#: never split out of the whole tail (final pass 8, #4: quadratic in markers).
_BREAKS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
_LINE = re.compile(f"[^{_BREAKS}]*(?:\r\n|[{_BREAKS}])?")
_BREAK = re.compile(f"[{_BREAKS}]")
#: One base64 body line, any length (a delta may cut it mid-line).
_B64_LINE = re.compile(r"[A-Za-z0-9+/]*={0,2}")
#: The start of an ``END`` marker a delta may have cut short.
_PARTIAL_END = re.compile(r"-{1,5}(?:E(?:N(?:D(?: [A-Z ]{0,64})?)?)?)?")
#: Masked delta text a block may carry before it is closed regardless.
MAX_OPEN_CHARS = 64 * 1024
_DELTA_WORDS = ("delta", "chunk", "partial")
_ANCHOR_KEYS = ("index", "content_index", "contentIndex", "message_id", "messageId", "role")
_NESTED = ("event", "data", "delta", "message", "part", "assistantMessageEvent")


def b64_body_end(text: str) -> int:
    """Where *text* stops being base64 body lines (``len(text)`` if it never does)."""
    offset = 0
    for piece in text.splitlines(keepends=True):
        if not _B64_LINE.fullmatch(piece.strip()):
            return offset
        offset += len(piece)
    return offset


def _kind(piece: str) -> str:
    """``blank``, ``header``, ``body`` (base64 or a cut ``END``) or ``prose``."""
    line = piece.strip()
    if _PARTIAL_END.fullmatch(line):
        return "body"
    core = key_body(line)
    if not core:
        return "blank"
    if HEADER.match(core):
        return "header"
    return "body" if _B64_LINE.fullmatch(core) else "prose"


def _lines(text: str, offset: int) -> Iterator[str]:
    """``text[offset:].splitlines(keepends=True)``, one line at a time."""
    position, size = offset, len(text)
    while position < size:
        match = _LINE.match(text, position)
        assert match is not None and match.end() > position
        yield match.group(0)
        position = match.end()


def key_end(text: str, offset: int, *, continuing: bool = False, stop: int | None = None) -> int:
    """End of the key material in *text* from *offset* (just past a marker).

    The rest of the marker's own line counts only when it is base64; then
    header lines, the one blank line after them, and base64 lines -- each with
    any tool decoration (``cat -n``, ``# ``, ``> ``) stripped first. The first
    line of anything else -- prose, a shell command, a second blank line -- ends
    the key and is not masked. *continuing*: *text* is a later delta of an open
    block, whose first piece finishes a line the previous delta began and whose
    blank lines may sit between an earlier delta's headers and its body.
    *stop*: where the next marker starts; on the marker's own line it makes that
    line prose at once, without reading the rest of it.
    """
    if stop is not None and _BREAK.search(text, offset, stop) is None:
        head = text[offset:stop]  # a line holding a marker is prose, unless a header
        if "\x1b" not in head and _kind(head) != "header":
            return offset
    position = offset
    headers = body = False
    pieces = _lines(text, offset)
    piece = next(pieces, None)
    index = 0
    while piece is not None:
        following = next(pieces, None)
        kind = _kind(piece)
        if kind == "prose":
            return position
        if kind == "blank" and index > 0 and (body or not headers):
            if not (continuing and _kind(following or "") in ("body", "blank")):
                return position
        headers = headers or kind == "header"
        body = body or kind == "body"
        position += len(piece)
        piece, index = following, index + 1
    return position


def masked_text(text: str) -> str:
    """*text* with each ``BEGIN``..``END`` span -- or, unterminated, ``BEGIN`` and
    the key material after it -- as the label. Prose after the key is kept.

    Linear in *text*: ``END`` is searched forward once and reused while it lies
    ahead, and an unterminated marker's key stops at the next marker's line.
    """
    begin = BEGIN.search(text)
    if begin is None:
        return text
    out: list[str] = []
    position = 0
    end = END.search(text, begin.end())
    while begin is not None:
        out.append(text[position : begin.start()])
        out.append(PLACEHOLDER)
        if end is not None and end.start() < begin.end():
            end = END.search(text, begin.end())
        if end is not None:
            position = end.end()
            begin = BEGIN.search(text, position)
            continue
        following = BEGIN.search(text, begin.end())
        position = key_end(text, begin.end(), stop=following.start() if following else None)
        if following is not None and following.start() < position:
            following = BEGIN.search(text, position)
        begin = following
    out.append(text[position:])
    return "".join(out)


def open_after(text: str) -> bool:
    """Whether *text*'s last ``BEGIN`` is unterminated with its key running to the end."""
    begins = list(BEGIN.finditer(text))
    if not begins or END.search(text, begins[-1].end()):
        return False
    return key_end(text, begins[-1].end()) == len(text)


def continued(text: str) -> int:
    """How much of a delta that continues an open block is still key material."""
    return key_end(text, 0, continuing=True)


def delta_like(event: object) -> bool:
    """Whether *event* is one streamed piece of a message, not a whole event."""
    if not isinstance(event, dict):
        return False
    if event.get("delta") is True or event.get("type") == "text":
        return True  # gemini's ``delta: true``; hermes streams answer text as ``text``
    for node in (event, *(event.get(key) for key in _NESTED)):
        if isinstance(node, dict):
            kind = node.get("type")
            if isinstance(kind, str) and any(word in kind.lower() for word in _DELTA_WORDS):
                return True
            if isinstance(node.get("delta"), (dict, str)):
                return True
    return False


def anchor(event: object) -> tuple[object, ...]:
    """The stream position a delta belongs to (message, content block, role)."""
    if not isinstance(event, dict):
        return ()
    found: list[object] = []
    for node in (event, *(event.get(key) for key in _NESTED)):
        if isinstance(node, dict):
            for key in _ANCHOR_KEYS:
                value = node.get(key)
                if isinstance(value, (str, int)) and not isinstance(value, bool):
                    found.append((key, value))
    return tuple(found)


__all__ = [
    "MAX_OPEN_CHARS",
    "anchor",
    "b64_body_end",
    "continued",
    "delta_like",
    "key_end",
    "masked_text",
    "open_after",
]
