"""Private-key block redaction for ``opentine.redaction``.

Split out of ``redaction`` for the module line cap when the depth bound and the
UTF-8 backstop landed there. A stdlib-only leaf with no ``opentine`` imports, so
importing it adds no edge to any layer. Every scan here is *iterative* — a cursor
walking lines of base64 — so the size or nesting of a blob never touches the
stack, which is the property the recursion audit needs from this half.
"""

from __future__ import annotations

import re

from opentine._redact_edits import Edit, apply

_LABEL = b"[REDACTED PRIVATE KEY]"
# "( BLOCK)?" covers OpenPGP armor ("-----BEGIN PGP PRIVATE KEY BLOCK-----"); the
# four-dash form is RFC 4716 / ssh.com ("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----").
_PRIVATE_KEY_BEGIN = re.compile(
    rb"-----BEGIN [A-Z ]{0,64}PRIVATE KEY(?: BLOCK)?-----"
    rb"|---- BEGIN SSH2 [A-Z ]{0,64}PRIVATE KEY ----"
)
_PRIVATE_KEY_END = re.compile(
    rb"-----END [A-Z ]{0,64}PRIVATE KEY(?: BLOCK)?-----|---- END SSH2 [A-Z ]{0,64}PRIVATE KEY ----"
)
_PEM_DATA = re.compile(rb"[A-Za-z0-9+/]{4,}={0,2}")
#: The RFC 1421 headers OpenSSL writes inside a *passphrase-encrypted* private-key
#: block, which sit between the BEGIN marker and the body and are separated from it
#: by one blank line. Only these two literal names: the blank line otherwise ends
#: the key material, so anything looser would let ordinary "error: ..." diagnostics
#: after a truncated marker be swallowed as key material.
#: RFC 4716 blocks carry ``Comment:``/``Subject:``/``x-…:`` headers instead, directly
#: before the body with no blank line.
_PEM_HEADER = re.compile(rb"(?i)(?:proc-type|dek-info|comment|subject|x-[a-z0-9-]{1,32}):")
#: OpenPGP armor headers (RFC 4880 ``Version:``, ``Hash:``, ``Charset:``, …) and any
#: other ``Name:`` line -- accepted only in the header block directly after the
#: marker, and only when key material follows it (:func:`_header_block_end`), so an
#: ``error: …`` diagnostic after a truncated marker is still kept.
_ARMOR_HEADER = re.compile(rb"[A-Za-z][A-Za-z0-9-]{0,32}:")
#: Per-line decoration in front of a body line: a line number (the Read tool's
#: ``N→``, ``cat -n``'s tab, ``nl``), a diff or quote marker, an indent.
_DECOR = re.compile(rb"[ \t]*(?:\d{1,9}(?:\xe2\x86\x92|\t|:| {1,2}))?[ \t]*(?:[+>|-][ \t]?)?[ \t]*")

#: Shortest leading base64 run treated as key material rather than prose. A PEM
#: body line is 64 characters and a real key is far longer, while an English word
#: that happens to be base64-shaped ("note", "parser") is short — so this is what
#: separates "-----BEGIN … MIIEvQIB…" from "-----BEGIN … note: parser saw a marker".
_PEM_RUN_MINIMUM = 40
#: Punctuation allowed between the marker and the key material, skipped before the
#: run is measured. Whitespace alone was not enough: a PEM carried *inside* JSON has
#: its line breaks as the two characters ``\`` ``n``, and a quote or brace may sit
#: there too, so the run began on a byte base64 has no room for and the scanner
#: found nothing — the leak 4894a3e closed, reopened by one escape character. Bounded
#: to a short run, and prose still fails the length floor below.
_PEM_SEPARATOR = re.compile(rb"[\s\"'\\,:;=(){}\[\]]{0,8}")


def _pem_run(value: bytes, offset: int, limit: int) -> int:
    """End of the key-material run starting at ``offset``, or ``offset`` if none.

    Requiring the *whole* remainder to be PEM data (``fullmatch``) meant a single
    trailing byte defeated it: for ``{"k": "-----BEGIN PRIVATE KEY-----MIIE…"}``
    the closing quote and brace made the match fail, so the scanner gave up and
    the key was emitted verbatim immediately after "[REDACTED PRIVATE KEY]" —
    output that reads as redacted while leaking every byte. Consuming the leading
    run instead removes exactly the key and keeps the surrounding diagnostics.
    """
    start = _PEM_SEPARATOR.match(value, offset, limit)
    match = _PEM_DATA.match(value, start.end() if start else offset, limit)
    if match is None or match.end() - match.start() < _PEM_RUN_MINIMUM:
        return offset
    return match.end()


def _undecorated(line: bytes) -> bytes:
    return line[_DECOR.match(line).end() :].strip()


def _header_block_end(value: bytes, cursor: int) -> int | None:
    """End of an armor-header block starting at *cursor*, when key material follows.

    Header lines, then at most one blank line, then a body line (pure base64, at
    least the run minimum). Anything else is not a header block, and the caller
    stops where it would have. Each line is read once: the caller resumes after it.
    """
    while cursor < len(value):
        line_end = value.find(b"\n", cursor)
        line_end = len(value) if line_end < 0 else line_end
        line = _undecorated(value[cursor:line_end])
        if _ARMOR_HEADER.match(line) or _PEM_HEADER.match(line):
            cursor = line_end + 1
            continue
        if not line:
            nxt = value.find(b"\n", line_end + 1)
            body = _undecorated(value[line_end + 1 : len(value) if nxt < 0 else nxt])
        else:
            body = line
        if len(body) >= _PEM_RUN_MINIMUM and _PEM_DATA.fullmatch(body):
            return cursor
        return None
    return None


def _trailing_text(value: bytes, offset: int) -> int:
    """End of the key material following an unterminated BEGIN marker.

    A blank line ends the body, which is what keeps separated diagnostics out of
    the redaction. An *encrypted* block writes ``Proc-Type``/``DEK-Info`` headers
    and then exactly one blank line before its body, so that rule alone stopped at
    the separator and emitted every key byte after it verbatim, immediately behind
    "[REDACTED PRIVATE KEY]" — the same shape 4894a3e fixed for the unencrypted
    case. The header block is therefore consumed along with the single blank line
    that closes it, and only then does a blank line mean "the key ended". OpenPGP
    armor (``Version:``, ``Hash:``) counts as a header block when a body follows it,
    and each line is read past its decoration (line numbers, ``> ``, ``+``, indent),
    so a numbered or quoted truncated key is no longer kept line by line.
    """
    line_end = value.find(b"\n", offset)
    if line_end < 0:
        if _PRIVATE_KEY_BEGIN.search(value, offset):
            return len(value)
        return _pem_run(value, offset, len(value))
    same_line = value[offset:line_end].strip()
    if same_line and not (_PRIVATE_KEY_BEGIN.search(same_line) or _PEM_DATA.fullmatch(same_line)):
        return _pem_run(value, offset, line_end)
    cursor = line_end + 1
    headers = False
    body = False
    while cursor < len(value):
        line_end = value.find(b"\n", cursor)
        line_end = len(value) if line_end < 0 else line_end
        line = _undecorated(value[cursor:line_end])
        if _PEM_HEADER.match(line):
            headers = True
        elif not body and not headers and _ARMOR_HEADER.match(line):
            if _header_block_end(value, cursor) is None:
                return cursor
            headers = True
        elif headers and _ARMOR_HEADER.match(line) and not body:
            pass
        elif not line and headers:
            headers = False  # the one blank line RFC 1421 puts before the body
        elif not line or not _PEM_DATA.fullmatch(line):
            return cursor
        else:
            body = True
        cursor = line_end + 1
    return len(value)


def _before_break(value: bytes, floor: int, end: int) -> int:
    """*end* moved back before the line break that ends the key material, so the
    next line keeps its line start for the line-anchored rules after this step
    (a blank line next already gives the line after it one)."""
    if value[end : end + 1] in (b"\n", b"\r"):
        return end
    if end > floor and value[end - 1 : end] == b"\n":
        end -= 1
        if end > floor and value[end - 1 : end] == b"\r":
            end -= 1
    return end


def redact_private_keys(value: bytes) -> bytes:
    """Replace every PEM private-key block, and only the key material, with a label.

    ``unterminated`` is what keeps this scan linear, the property
    ``test_release_audit_round4`` holds the whole module to. Searching for the END
    marker reads to the end of the blob when there is none, so a blob carrying *k*
    unterminated markers paid that walk *k* times: 8000 of them across 400KB took
    4.6s, and the cost is quadratic in a blob a recorded model response controls.
    The searches only ever start later than the one before, so once a marker finds
    no END, no later marker can find one either and the walk is not worth repeating.
    """
    return apply(value, private_key_edits(value))


def private_key_edits(value: bytes) -> list[Edit]:
    """The edits :func:`redact_private_keys` makes: each block becomes its label."""
    edits: list[Edit] = []
    cursor = 0
    unterminated = False
    while begin := _PRIVATE_KEY_BEGIN.search(value, cursor):
        end = None if unterminated else _PRIVATE_KEY_END.search(value, begin.end())
        if end is None:
            unterminated = True
            cursor = _trailing_text(value, begin.end())
            edits.append((begin.start(), _before_break(value, begin.end(), cursor), _LABEL))
            if cursor == len(value):
                return edits
            continue
        cursor = end.end()
        edits.append((begin.start(), cursor, _LABEL))
    return edits
