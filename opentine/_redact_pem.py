"""Private-key block redaction for ``opentine.redaction``.

Split out of ``redaction`` for the module line cap when the depth bound and the
UTF-8 backstop landed there. A stdlib-only leaf with no ``opentine`` imports, so
importing it adds no edge to any layer. Every scan here is *iterative* — a cursor
walking lines of base64 — so the size or nesting of a blob never touches the
stack, which is the property the recursion audit needs from this half.
"""

from __future__ import annotations

import re

_PRIVATE_KEY_BEGIN = re.compile(rb"-----BEGIN [A-Z ]{0,64}PRIVATE KEY-----")
_PRIVATE_KEY_END = re.compile(rb"-----END [A-Z ]{0,64}PRIVATE KEY-----")
_PEM_DATA = re.compile(rb"[A-Za-z0-9+/]{4,}={0,2}")
#: The RFC 1421 headers OpenSSL writes inside a *passphrase-encrypted* private-key
#: block, which sit between the BEGIN marker and the body and are separated from it
#: by one blank line. Only these two literal names: the blank line otherwise ends
#: the key material, so anything looser would let ordinary "error: ..." diagnostics
#: after a truncated marker be swallowed as key material.
_PEM_HEADER = re.compile(rb"(?i)(?:proc-type|dek-info):")

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


def _trailing_text(value: bytes, offset: int) -> int:
    """End of the key material following an unterminated BEGIN marker.

    A blank line ends the body, which is what keeps separated diagnostics out of
    the redaction. An *encrypted* block writes ``Proc-Type``/``DEK-Info`` headers
    and then exactly one blank line before its body, so that rule alone stopped at
    the separator and emitted every key byte after it verbatim, immediately behind
    "[REDACTED PRIVATE KEY]" — the same shape 4894a3e fixed for the unencrypted
    case. The header block is therefore consumed along with the single blank line
    that closes it, and only then does a blank line mean "the key ended".
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
    while cursor < len(value):
        line_end = value.find(b"\n", cursor)
        line_end = len(value) if line_end < 0 else line_end
        line = value[cursor:line_end].strip()
        if _PEM_HEADER.match(line):
            headers = True
        elif not line and headers:
            headers = False  # the one blank line RFC 1421 puts before the body
        elif not line or not _PEM_DATA.fullmatch(line):
            return cursor
        cursor = line_end + 1
    return len(value)


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
    output = bytearray()
    cursor = 0
    unterminated = False
    while begin := _PRIVATE_KEY_BEGIN.search(value, cursor):
        output.extend(value[cursor : begin.start()])
        output.extend(b"[REDACTED PRIVATE KEY]")
        end = None if unterminated else _PRIVATE_KEY_END.search(value, begin.end())
        if end is None:
            unterminated = True
            cursor = _trailing_text(value, begin.end())
            if cursor == len(value):
                return bytes(output)
            continue
        cursor = end.end()
    output.extend(value[cursor:])
    return bytes(output)
