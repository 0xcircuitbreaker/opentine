"""Credentials disguised from the shape scan, and high-entropy values under key names.

A stdlib-only leaf for the module line cap. Two scan steps:

* :func:`disguised_edits` finds a token-character run that carries URL escapes
  (``sk%2Dant-…``), zero-width or soft-hyphen characters (``ghp_\\u200babc…``) or
  fullwidth letters, normalizes it (zero-width removed, NFKC, percent-decoded)
  and redacts the whole run when the normalized text holds a known token shape.
* :func:`entropy_edits` redacts a long, mixed-alphabet, high-entropy value assigned
  to a key-ish name the name rules do not list (``ACME_SIGNKEY: Xy9…``,
  ``mykey = Xy9…``), the fallback for vendors with no fixed prefix.

Every pattern is a single bounded run, so a scan stays linear in its input.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from urllib.parse import unquote

from opentine._redact_edits import Edit
from opentine._redact_shapes import TOKEN_SHAPES

#: Version of the credential rules a run was redacted under, recorded in its
#: ``RedactionPolicy``. Runs without it predate 0.35 (ruleset 1); both verify.
REDACTION_RULESET = "opentine-redaction/2"

_ZERO_WIDTH = "​‌‍⁠﻿­"
# Token characters, URL escapes, zero-width/soft-hyphen and fullwidth ASCII bytes.
_RUN = re.compile(
    rb"(?:[A-Za-z0-9_.~+/=-]|%[0-9A-Fa-f]{2}|\xe2\x80[\x8b-\x8d]|\xe2\x81\xa0"
    rb"|\xef\xbb\xbf|\xc2\xad|\xef\xbc[\x81-\xbf]|\xef\xbd[\x80-\x9e]){16,4096}"
)
_DISGUISE = re.compile(
    rb"%[0-9A-Fa-f]{2}|\xe2\x80[\x8b-\x8d]|\xe2\x81\xa0|\xef[\xbb\xbc\xbd]|\xc2\xad"
)
_ZW_TABLE = {ord(char): None for char in _ZERO_WIDTH}


def _normalized(run: bytes) -> bytes:
    text = unicodedata.normalize("NFKC", run.decode("utf-8").translate(_ZW_TABLE))
    return unquote(text).translate(_ZW_TABLE).encode("utf-8", "replace")


def disguised_edits(value: bytes) -> list[Edit]:
    edits: list[Edit] = []
    for match in _RUN.finditer(value):
        run = match.group(0)
        if _DISGUISE.search(run) and TOKEN_SHAPES.search(_normalized(run)):
            edits.append((match.start(), match.end(), b"[REDACTED]"))
    return edits


# A name with a key-ish word, its separator (optionally quoted), and a value run.
_KEYED = re.compile(
    rb"(?<![A-Za-z0-9_.:-])([A-Za-z][A-Za-z0-9_.-]{0,63})([\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?)"
    rb"([A-Za-z0-9+/_.=-]{20,512})(?![A-Za-z0-9+/_.=(\[-])"
)
_KEYISH = re.compile(r"(?i)key|token|secret|auth|passw|pwd|cred")
# Names that hold public or non-secret identifiers despite the key-ish word.
_BENIGN = re.compile(
    r"(?i)public|pub_|publishable|idempotency|cache|sort|primary|foreign|partition|"
    r"_id$|hash|digest|fingerprint|checksum|keyword|tokens?_?(?:count|usage)|^key_?id"
)


def _entropy(text: bytes) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _secretish(raw: bytes) -> bool:
    if not (re.search(rb"[a-z]", raw) and re.search(rb"[A-Z]", raw) and re.search(rb"[0-9]", raw)):
        return False  # hex digests, words and paths are single- or two-class
    if raw.count(b".") + raw.count(b"/") > 2:
        return False  # dotted module paths, file paths
    return _entropy(raw) >= 4.0


def entropy_edits(value: bytes) -> list[Edit]:
    edits: list[Edit] = []
    for match in _KEYED.finditer(value):
        name = match.group(1).decode("ascii")
        if _KEYISH.search(name) and not _BENIGN.search(name) and _secretish(match.group(3)):
            edits.append((match.start(3), match.end(3), b"[REDACTED]"))
    return edits


__all__ = ["REDACTION_RULESET", "disguised_edits", "entropy_edits"]
