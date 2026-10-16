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
from opentine._redact_edits import Edit, Step, run, sub_step
from opentine._redact_fields import FIELD, NAME_TAIL, quoted_field_edits
from opentine._redact_flags import flag_edits
from opentine._redact_forms import B64_KEY_STEP, FORM_STEPS
from opentine._redact_json import redact_json
from opentine._redact_names import secret_name
from opentine._redact_pem import private_key_edits
from opentine._redact_ppk import ppk_edits
from opentine._redact_shapes import QUERY_SECRET, TOKEN_SHAPES, URL_USERINFO
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
# An optional single leading "_" after the dashes (".npmrc"'s "//host/:_authToken=")
# is one fixed character, so it adds no split ambiguity to the scan. The vendor
# *_TOKEN / *_KEY compounds name credentials outright; bare "token"/"key" stay out.
_NAME = (
    rb"(?<![A-Za-z0-9_-])(?:-{1,2})?_?(?:[A-Za-z0-9]+[_-])*"
    rb"[A-Za-z0-9]*"
    rb"(?:api[_-]?keys?|api[_-]?tokens?|access[_-]?keys?|access[_-]?tokens?|"
    rb"secret[_-]?access[_-]?keys?|secret[_-]?keys?|private[_-]?keys?|"
    rb"refresh[_-]?tokens?|session[_-]?tokens?|auth[_-]?tokens?|id[_-]?tokens?|"
    rb"(?:github|gh|hf|npm|pypi|gitlab|bot|slack|discord|telegram|vault|private|"
    rb"security|registry|personal[_-]?access)[_-]?tokens?|"
    rb"(?:subscription|account|signing|encryption|master|ssh|storage)[_-]?keys?|key[_-]data|"
    rb"client[_-]?secrets?|passwords?|passwd|passphrases?|apikey|credentials?|secrets?|"
    rb"private[_-]?key[_-]?ids?|connection[_-]?strings?|webhook[_-]?urls?|dsn)"
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
# No leading \b: it fails between a space and the "-" of "--api-key=…", and _NAME's
# lookbehind is the stricter start gate. Quotes are excluded from the unquoted class so
# a JSON string value ends at its closing quote (consuming it made '{"note": "the
# api_key: [REDACTED], "user": "bob"}', unparseable). A quoted value has its own
# alternative, redacted inside the quotes by _assignment: with only the unquoted class
# 'the password: "hunter2" is old' backtracked to the lone space and wrote a false
# marker beside the secret, so the unquoted class starts with a non-space character.
# The closing quote is optional so a truncated 'api_key: "abc' is still redacted.
# Unquoted values go word by word and stop only before a next credential-name head
# (``[-e ]NAME=``), so ``-e A_KEY=x -e B_PASSWORD="y"`` still matches twice while
# base64 padding (``Basic dXNl…=``) or a ``user:pass`` word stays inside the value.
_NEXT_HEAD = rb"(?!(?:-{1,2}[A-Za-z]+[^\S\r\n]+)?" + _NAME + rb"[ \t]*[:=])"
_ASSIGNMENT = re.compile(
    rb"(?i)(" + _NAME + rb")(\s*[:=]\s*)"
    rb"(\"[^\"\r\n]*\"?|'[^'\r\n]*'?|[^\s,;\"']+(?:[^\S\r\n]+" + _NEXT_HEAD + rb"[^\s,;\"']+)*)"
)
_FIELD_NAME = re.compile(
    rb"(?i)" + _NAME + rb"|token|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie"
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
_PROSE_VALUES = {b"can", b"could", b"how", b"should", b"what", b"when", b"where", b"which", b"why"}


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


def _field_is_secret(name: bytes) -> bool:
    # The record walk's predicate (single source: ``_redact_names``), plus the
    # name pattern this rule always used, so no field it redacted is kept now.
    name = name[-NAME_TAIL:]
    return bool(_FIELD_NAME.fullmatch(name)) or secret_name(name.decode("ascii"))


def _quoted_field_edits(value: bytes) -> list[Edit]:
    return quoted_field_edits(FIELD, value, _field_is_secret)


def redact_blob(value: bytes) -> bytes:
    """Scrub credential-shaped UTF-8 text; JSON stays valid JSON (``_redact_json``)."""
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        return value
    return redact_json(value, _scan, STEPS)


def _keep_ends(match: re.Match[bytes]) -> bytes:
    return match.group(1) + b"[REDACTED]" + match.group(3)


def _keep_head(match: re.Match[bytes]) -> bytes:
    return match.group(1) + b"[REDACTED]"


#: The byte scan, in order. ``_redact_json`` also runs each step alone to find
#: where a step would remove something. Private-key blocks go first, PEM and
#: base64-wrapped alike: a value pattern that runs across a JSON-escaped ``\\n``
#: (``MYSQL_PWD=x\\n-----BEGIN``) or takes a wrapped key's first line
#: (``SSH_PRIVATE_KEY=LS0t…``) would otherwise leave the key body behind.
STEPS: list[Step] = [
    private_key_edits,
    ppk_edits,  # PuTTY key files carry no PEM marker (``_redact_ppk``)
    B64_KEY_STEP,
    _quoted_field_edits,
    *(sub_step(p, _keep_ends) for p in (_NAMED_HEADER, _REVERSED_NAMED_HEADER, _HEADER_PAIR)),
    *(sub_step(p, _keep_ends) for p in (_QUOTED_HEADER_LINE, _QUOTED_HEADER, _QUOTED_TOKEN)),
    sub_step(_LINE_ASSIGNMENT, _keep_head),
    sub_step(_HEADER_LINE, _keep_head),
    sub_step(_ASSIGNMENT, _assignment),
    sub_step(_BEARER, _keep_head),
    flag_edits,  # ``--password x`` / ``--token "x"`` (``_redact_flags``)
    # Tokens before the bounded form values, so a value cut at its bound cannot take
    # a token's prefix and leave the rest behind (see also ``_redact_tails``).
    sub_step(TOKEN_SHAPES, b"[REDACTED]"),
    sub_step(URL_USERINFO, _keep_ends),
    sub_step(QUERY_SECRET, _keep_head),
    *FORM_STEPS,
]


def _scan(value: bytes) -> bytes:
    return run(value, STEPS)


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
        clean = redact_blob(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        assert_unicode_text(value, where="the value being redacted")
        raise ValueError(f"value is not UTF-8 text: {exc.reason}") from exc
    # Edits end on character boundaries (``_redact_edits``); this is the backstop,
    # so a text value never surfaces a codec error from inside a save.
    return clean.decode("utf-8", "replace")


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
