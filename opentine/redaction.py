"""Typed/path-aware client-side redaction for v3 object creation."""

from __future__ import annotations

import re
from typing import Any

# A credential-bearing identifier: an optional vendor/scope prefix (OPENAI_, X-, AWS_, …)
# followed by an unambiguous credential compound. Bare "token"/"key" are intentionally
# excluded so numeric usage counters (input_tokens, cached_tokens, reasoning_tokens) and
# benign names (public_key, idempotency_key) are never scrubbed.
# "--api-key=SECRET" (captured argv) and "-API_KEY=SECRET" (a diff removal line for
# a .env file) are routine ways a credential reaches a trace, so a leading dash run
# is consumed explicitly. It must be consumed *after* the boundary check rather
# than by widening the lookbehind to allow a preceding "-": that would make every
# hyphen in the input a candidate start position and turn matching quadratic on
# input like "a-b_c-d_"*1500 (see the linearity assertion in test_release_audit_round4).
_NAME = (
    rb"(?<![A-Za-z0-9_-])(?:-{1,2})?(?:[A-Za-z0-9]+[_-])*"
    rb"[A-Za-z0-9]*"
    rb"(?:api[_-]?keys?|api[_-]?tokens?|access[_-]?keys?|access[_-]?tokens?|"
    rb"secret[_-]?access[_-]?keys?|secret[_-]?keys?|private[_-]?keys?|"
    rb"refresh[_-]?tokens?|session[_-]?tokens?|auth[_-]?tokens?|id[_-]?tokens?|"
    rb"client[_-]?secrets?|passwords?|passwd|passphrases?|apikey|credentials?|secrets?)"
)
# `[ \t]*(?:[+>-][ \t]*)?` rather than `[ \t]*[+>-]?[ \t]*`: two adjacent runs of
# optional whitespace give O(n) ways to split n leading spaces, so a failing match
# backtracks through every split and the scan turns quadratic in indentation. Ordinary
# indented JSON blew past the 1.5s linearity budget at a few hundred KB. Nesting the
# whitespace inside the marker alternative makes the split unique without changing
# which strings match.
_LINE_ASSIGNMENT = re.compile(
    rb"(?im)^([ \t]*(?:[+>-][ \t]*)?(?:(?:export|set)[ \t]+)?(?:\$env[ \t]*:[ \t]*)?"
    + _NAME
    + rb"[ \t]*[:=][ \t]*)([^\r\n]*)"
)
# No leading \b: it fails between a space and the "-" of a mid-line "--api-key=…"
# flag, and _NAME's own lookbehind is already the stricter start-boundary gate.
# Quotes excluded from the value class so a JSON string value ends at its closing
# quote. Consuming it produced '{"note": "the api_key: [REDACTED], "user": "bob"}'
# — no longer parseable, so every downstream reader fell back to treating the whole
# blob as opaque text.
_ASSIGNMENT = re.compile(rb"(?i)(" + _NAME + rb")(\s*[:=]\s*)([^\r\n,;\"']+)")
_QUOTED_FIELD = re.compile(
    rb"(?i)([\"'](?:"
    + _NAME
    + rb"|token|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie)"
    rb"[\"']\s*:\s*)([\"'])"
)
_BEARER = re.compile(rb"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_QUOTED_HEADER = re.compile(
    rb"(?i)([\"'](?:authorization|proxy[_-]?authorization|cookie|set[_-]?cookie)[\"']\s*:\s*[\"'])([^\"']*)([\"'])"
)
_HEADER_PAIR = re.compile(
    rb"(?i)(\[\s*[\"'](?:"
    + _NAME
    + rb"|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie)"
    + rb"[\"']\s*,\s*[\"'])([^\"']*)([\"'])"
)
_QUOTED_HEADER_LINE = re.compile(
    rb"(?i)([\"'](?:authorization|proxy[-_]authorization|cookie|set[-_]cookie)\s*[:=]\s*)"
    rb"([^\"'\r\n]*)([\"'])"
)
_NAMED_HEADER = re.compile(
    rb"(?i)([\"']name[\"']\s*:\s*[\"'](?:"
    + _NAME
    + rb"|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie)"
    + rb"[\"']\s*,\s*[\"']value[\"']\s*:\s*[\"'])([^\"']*)([\"'])"
)
_REVERSED_NAMED_HEADER = re.compile(
    rb"(?i)([\"']value[\"']\s*:\s*[\"'])([^\"']*)([\"']\s*,\s*[\"']name[\"']\s*:\s*"
    rb"[\"'](?:" + _NAME + rb"|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie)[\"'])"
)
_HEADER_LINE = re.compile(
    rb"(?im)^([ \t]*(?:[+>-][ \t]*)?(?:authorization|proxy[-_]authorization|cookie|set[-_]cookie)"
    rb"[ \t]*[:=][ \t]*)([^\r\n]*)"
)
_QUOTED_TOKEN = re.compile(rb"(?i)([\"']token[\"']\s*:\s*[\"'])([^\"']*)([\"'])")
_PRIVATE_KEY_BEGIN = re.compile(rb"-----BEGIN [A-Z ]{0,64}PRIVATE KEY-----")
_PRIVATE_KEY_END = re.compile(rb"-----END [A-Z ]{0,64}PRIVATE KEY-----")
_PEM_DATA = re.compile(rb"[A-Za-z0-9+/]{4,}={0,2}")
# High-confidence secret token shapes, scrubbed regardless of the surrounding field name.
_TOKEN_SHAPES = re.compile(
    rb"(?i)\b(?:"
    rb"sk-[A-Za-z0-9_-]{16,}"  # OpenAI / Anthropic style
    rb"|AKIA[0-9A-Z]{16}"  # AWS access key id
    rb"|gh[opsu]_[A-Za-z0-9]{20,}"  # GitHub tokens
    rb"|xox[baprs]-[A-Za-z0-9-]{10,}"  # Slack tokens
    rb")"
)
_PROSE_VALUES = {
    b"can",
    b"could",
    b"how",
    b"should",
    b"what",
    b"when",
    b"where",
    b"which",
    b"why",
}


def _assignment(match: re.Match[bytes]) -> bytes:
    separator, candidate = match.group(2), match.group(3)
    first = candidate.split()[0].lower() if candidate.split() else candidate.lower()
    if b":" in separator and first in _PROSE_VALUES:
        return match.group(0)
    return match.group(1) + separator + b"[REDACTED]"


def _quoted_fields(value: bytes) -> bytes:
    output = bytearray()
    cursor = 0
    while match := _QUOTED_FIELD.search(value, cursor):
        output.extend(value[cursor : match.end()])
        quote = match.group(2)[0]
        end = match.end()
        while end < len(value) and value[end] not in (10, 13):
            if value[end] == quote:
                output.extend(b"[REDACTED]" + bytes((quote,)))
                cursor = end + 1
                break
            end += 2 if value[end] == 92 and end + 1 < len(value) else 1
        else:
            output.extend(b"[REDACTED]")
            cursor = end
    output.extend(value[cursor:])
    return bytes(output)


#: Shortest leading base64 run treated as key material rather than prose. A PEM
#: body line is 64 characters and a real key is far longer, while an English word
#: that happens to be base64-shaped ("note", "parser") is short — so this is what
#: separates "-----BEGIN … MIIEvQIB…" from "-----BEGIN … note: parser saw a marker".
_PEM_RUN_MINIMUM = 40


def _pem_run(value: bytes, offset: int, limit: int) -> int:
    """End of the key-material run starting at ``offset``, or ``offset`` if none.

    Requiring the *whole* remainder to be PEM data (``fullmatch``) meant a single
    trailing byte defeated it: for ``{"k": "-----BEGIN PRIVATE KEY-----MIIE…"}``
    the closing quote and brace made the match fail, so the scanner gave up and
    the key was emitted verbatim immediately after "[REDACTED PRIVATE KEY]" —
    output that reads as redacted while leaking every byte. Consuming the leading
    run instead removes exactly the key and keeps the surrounding diagnostics.
    """
    span = value[offset:limit]
    match = _PEM_DATA.match(value, offset + len(span) - len(span.lstrip()), limit)
    if match is None or match.end() - match.start() < _PEM_RUN_MINIMUM:
        return offset
    return match.end()


def _trailing_text(value: bytes, offset: int) -> int:
    line_end = value.find(b"\n", offset)
    if line_end < 0:
        if _PRIVATE_KEY_BEGIN.search(value, offset):
            return len(value)
        return _pem_run(value, offset, len(value))
    same_line = value[offset:line_end].strip()
    if same_line and not (_PRIVATE_KEY_BEGIN.search(same_line) or _PEM_DATA.fullmatch(same_line)):
        return _pem_run(value, offset, line_end)
    cursor = line_end + 1
    while cursor < len(value):
        line_end = value.find(b"\n", cursor)
        line_end = len(value) if line_end < 0 else line_end
        line = value[cursor:line_end].strip()
        if not line:
            return cursor
        if not _PEM_DATA.fullmatch(line):
            return cursor
        cursor = line_end + 1
    return len(value)


def _private_keys(value: bytes) -> bytes:
    output = bytearray()
    cursor = 0
    while begin := _PRIVATE_KEY_BEGIN.search(value, cursor):
        output.extend(value[cursor : begin.start()])
        output.extend(b"[REDACTED PRIVATE KEY]")
        end = _PRIVATE_KEY_END.search(value, begin.end())
        if end is None:
            cursor = _trailing_text(value, begin.end())
            if cursor == len(value):
                return bytes(output)
            continue
        cursor = end.end()
    output.extend(value[cursor:])
    return bytes(output)


def redact_blob(value: bytes) -> bytes:
    """Scrub credential-shaped UTF-8 text while leaving opaque binary intact."""
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        return value
    value = _quoted_fields(value)
    value = _NAMED_HEADER.sub(lambda match: match.group(1) + b"[REDACTED]" + match.group(3), value)
    value = _REVERSED_NAMED_HEADER.sub(
        lambda match: match.group(1) + b"[REDACTED]" + match.group(3), value
    )
    value = _HEADER_PAIR.sub(lambda match: match.group(1) + b"[REDACTED]" + match.group(3), value)
    value = _QUOTED_HEADER_LINE.sub(
        lambda match: match.group(1) + b"[REDACTED]" + match.group(3), value
    )
    value = _QUOTED_HEADER.sub(lambda match: match.group(1) + b"[REDACTED]" + match.group(3), value)
    value = _QUOTED_TOKEN.sub(lambda match: match.group(1) + b"[REDACTED]" + match.group(3), value)
    value = _LINE_ASSIGNMENT.sub(lambda match: match.group(1) + b"[REDACTED]", value)
    value = _HEADER_LINE.sub(lambda match: match.group(1) + b"[REDACTED]", value)
    value = _ASSIGNMENT.sub(_assignment, value)
    value = _BEARER.sub(lambda match: match.group(1) + b"[REDACTED]", value)
    value = _TOKEN_SHAPES.sub(b"[REDACTED]", value)
    return _private_keys(value)


def redact_value(value: Any) -> Any:
    """Scrub free-form strings inside an already type-redacted value."""
    if isinstance(value, str):
        return redact_blob(value.encode("utf-8")).decode("utf-8")
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            clean_key = redact_value(key) if isinstance(key, str) else key
            if clean_key in redacted:
                raise ValueError("redaction collapsed distinct object keys")
            redacted[clean_key] = redact_value(item)
        return redacted
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value
