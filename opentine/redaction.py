"""Typed/path-aware client-side redaction for v3 object creation."""

from __future__ import annotations

import re

# A credential-bearing identifier: an optional vendor/scope prefix (OPENAI_, X-, AWS_, …)
# followed by an unambiguous credential compound. Bare "token"/"key" are intentionally
# excluded so numeric usage counters (input_tokens, cached_tokens, reasoning_tokens) and
# benign names (public_key, idempotency_key) are never scrubbed.
_NAME = (
    rb"(?:[A-Za-z0-9]+[_-])*"
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
_HEADER_LINE = re.compile(
    rb"(?im)^([ \t]*(?:authorization|proxy-authorization|cookie|set-cookie)[ \t]*:[ \t]*)([^\r\n]*)"
)
_QUOTED_TOKEN = re.compile(rb"(?i)([\"']token[\"']\s*:\s*[\"'])([^\"']*)([\"'])")
_PRIVATE_KEY = re.compile(
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
# High-confidence secret token shapes, scrubbed regardless of the surrounding field name.
_TOKEN_SHAPES = re.compile(
    rb"(?i)\b(?:"
    rb"sk-[A-Za-z0-9_-]{16,}"  # OpenAI / Anthropic style
    rb"|AKIA[0-9A-Z]{16}"  # AWS access key id
    rb"|gh[opsu]_[A-Za-z0-9]{20,}"  # GitHub tokens
    rb"|xox[baprs]-[A-Za-z0-9-]{10,}"  # Slack tokens
    rb")"
)


def redact_blob(value: bytes) -> bytes:
    """Scrub credential-shaped UTF-8 text while leaving opaque binary intact."""
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        return value
    value = _QUOTED_HEADER.sub(lambda match: match.group(1) + b"[REDACTED]" + match.group(3), value)
    value = _QUOTED_TOKEN.sub(lambda match: match.group(1) + b"[REDACTED]" + match.group(3), value)
    value = _QUOTED_ASSIGNMENT.sub(
        lambda match: match.group(1) + b"[REDACTED]" + match.group(3), value
    )
    value = _HEADER_LINE.sub(lambda match: match.group(1) + b"[REDACTED]", value)
    value = _ASSIGNMENT.sub(lambda match: match.group(1) + match.group(2) + b"[REDACTED]", value)
    value = _BEARER.sub(lambda match: match.group(1) + b"[REDACTED]", value)
    value = _TOKEN_SHAPES.sub(b"[REDACTED]", value)
    return _PRIVATE_KEY.sub(b"[REDACTED PRIVATE KEY]", value)
