"""Typed/path-aware client-side redaction for v3 object creation.

Two halves: ``redact_blob`` scrubs credential-shaped bytes with iterative regex
scans, and ``redact_value`` walks a decoded value tree. PEM private-key handling
lives in the stdlib-only leaf ``_redact_pem`` for the module line cap. Both
imports below are stdlib-only leaves themselves, so this module stays importable
from every layer that writes objects.
"""

from __future__ import annotations

import re
from typing import Any

from opentine._canon_redact import MAX_CANONICAL_DEPTH, _too_deep
from opentine._redact_pem import redact_private_keys
from opentine._unicode_text import assert_unicode_text

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
# Quotes excluded from the *unquoted* value class so a JSON string value ends at
# its closing quote. Consuming it produced '{"note": "the api_key: [REDACTED],
# "user": "bob"}' — no longer parseable, so every downstream reader fell back to
# treating the whole blob as opaque text. A quoted value therefore gets its own
# alternative instead, redacted *inside* the quotes by _assignment below: with only
# the unquoted class, 'the password: "hunter2" is old' backtracked the separator's
# trailing \s* and matched the lone space, writing 'password:[REDACTED]"hunter2"'
# — a false [REDACTED] marker with the secret still beside it. The unquoted class
# starts with a non-space character for that reason, and the closing quote is
# optional so a truncated 'api_key: "abc' is still redacted rather than skipped.
_ASSIGNMENT = re.compile(
    rb"(?i)(" + _NAME + rb")(\s*[:=]\s*)"
    rb"(\"[^\"\r\n]*\"?|'[^'\r\n]*'?|[^\s\r\n,;\"'][^\r\n,;\"']*)"
)
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
    quote = candidate[:1]
    if quote in (b'"', b"'"):
        # The quotes are the value's delimiters, not part of it: keeping them keeps
        # a JSON object parseable, exactly as _quoted_fields does for '"key": "…"'.
        closing = quote if len(candidate) > 1 and candidate.endswith(quote) else b""
        return match.group(1) + separator + quote + b"[REDACTED]" + closing
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
    return redact_private_keys(value)


def redact_text(value: str) -> str:
    """Scrub one string, refusing text UTF-8 has no spelling for.

    ``str.encode("utf-8")`` on an unpaired UTF-16 surrogate — what ``json.loads``
    hands back for a ``\\udXXX`` escape, i.e. a model response sliced mid-emoji —
    raises a bare ``UnicodeEncodeError`` naming a codec and a byte position, from
    inside a walk that cannot say which field it was reading. Callers that guard
    their whole payload (``_blob_guard``, ``repository/store``) report the JSON
    path; this is the backstop for the ones that reach a single value, so no
    caller ever surfaces a codec message as an opentine error.
    """
    try:
        return redact_blob(value.encode("utf-8")).decode("utf-8")
    except UnicodeEncodeError as exc:
        assert_unicode_text(value, where="the value being redacted")
        raise ValueError(f"value is not UTF-8 text: {exc.reason}") from exc


def redact_value(value: Any, _depth: int = 0) -> Any:
    """Scrub free-form strings inside an already type-redacted value.

    ``_depth`` is the bound ``_canon_redact._redact`` enforces, and this walk needs
    its own check rather than inheriting that one: it runs *after* ``_redact`` over
    the same value on the v3 write path, so it still sees everything ``_redact``
    admitted. Unbounded it raised ``RecursionError`` instead of a refusal — and at
    an interpreter-dependent depth, because the list branch was a comprehension
    (~498 levels on 3.11 against ~996 on 3.12+, PEP 709 having inlined
    comprehension frames in 3.12) while the tuple branch was a generator
    expression, which is *never* inlined and so cost two frames per level on every
    version. Both are statement loops below for that reason: one frame per nesting
    level everywhere, so every interpreter refuses the same input at the same
    depth. Cycles land here too — a self-referential container is infinitely deep.
    """
    if _depth > MAX_CANONICAL_DEPTH:
        raise _too_deep()
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            # Keys are strings, so scrub them directly instead of recursing: a key
            # is not a nesting level and must not spend one.
            clean_key = redact_text(key) if isinstance(key, str) else key
            if clean_key in redacted:
                raise ValueError("redaction collapsed distinct object keys")
            redacted[clean_key] = redact_value(item, _depth + 1)
        return redacted
    if isinstance(value, (list, tuple)):
        items: list[Any] = []
        for item in value:
            items.append(redact_value(item, _depth + 1))
        return tuple(items) if isinstance(value, tuple) else items
    return value
