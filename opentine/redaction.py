"""Typed/path-aware client-side redaction for v3 object creation."""

from __future__ import annotations

import re

# A credential-bearing identifier: an optional vendor/scope prefix (OPENAI_, X-, AWS_, …)
# followed by an unambiguous credential compound. Bare "token"/"key" are intentionally
# excluded so numeric usage counters (input_tokens, cached_tokens, reasoning_tokens) and
# benign names (public_key, idempotency_key) are never scrubbed.
_NAME = (
    rb"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9]+[_-])*"
    rb"(?:api[_-]?keys?|api[_-]?tokens?|access[_-]?keys?|access[_-]?tokens?|"
    rb"secret[_-]?access[_-]?keys?|secret[_-]?keys?|private[_-]?keys?|"
    rb"refresh[_-]?tokens?|session[_-]?tokens?|auth[_-]?tokens?|id[_-]?tokens?|"
    rb"client[_-]?secrets?|passwords?|passwd|passphrases?|apikey|credentials?|secrets?)"
)
_ASSIGNMENT = re.compile(rb"(?i)\b(" + _NAME + rb")(\s*[:=]\s*)([^\s,;\"']+)")
_QUOTED_ASSIGNMENT = re.compile(rb"(?i)([\"']" + _NAME + rb"[\"']\s*:\s*[\"'])([^\"']*)([\"'])")
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
    rb"(?i)([\"'](?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)([^\"'\r\n]*)([\"'])"
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
    rb"(?im)^([ \t]*(?:authorization|proxy-authorization|cookie|set-cookie)[ \t]*:[ \t]*)([^\r\n]*)"
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
    if b":" in separator and candidate.lower() in _PROSE_VALUES:
        return match.group(0)
    return match.group(1) + separator + b"[REDACTED]"


def _trailing_text(value: bytes, offset: int) -> int:
    line_end = value.find(b"\n", offset)
    if line_end < 0:
        return len(value)
    cursor = line_end + 1
    separated = False
    separator_start = cursor
    while cursor < len(value):
        line_end = value.find(b"\n", cursor)
        line_end = len(value) if line_end < 0 else line_end
        line = value[cursor:line_end].strip()
        if not line:
            if not separated:
                separator_start = cursor
            separated = True
        elif separated and not _PEM_DATA.fullmatch(line):
            return separator_start
        else:
            separated = False
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
    value = _QUOTED_ASSIGNMENT.sub(
        lambda match: match.group(1) + b"[REDACTED]" + match.group(3), value
    )
    value = _HEADER_LINE.sub(lambda match: match.group(1) + b"[REDACTED]", value)
    value = _ASSIGNMENT.sub(_assignment, value)
    value = _BEARER.sub(lambda match: match.group(1) + b"[REDACTED]", value)
    value = _TOKEN_SHAPES.sub(b"[REDACTED]", value)
    return _private_keys(value)
