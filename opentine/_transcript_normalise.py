"""Text normalisation before transcript features (0.74).

A run that wants to escape triage can rewrite its transcript so the words no
longer match known bad ones while a reader (or a shell) still sees the same
thing. Before features are taken, :func:`words` therefore:

* applies Unicode NFKC (full-width and other compatibility forms fold to
  their plain letters) and case folding;
* drops format characters (category ``Cf``: zero-width spaces and joiners,
  bidi controls, soft hyphens) so they cannot split a word;
* maps the common Cyrillic and Greek lookalikes of Latin letters to the Latin
  letter (a fixed table, :data:`CONFUSABLES`);
* decodes tokens that are valid base64 of UTF-8 text (at least
  ``B64_MIN`` characters, at most ``B64_MAX`` decoded bytes) and adds the
  decoded words after the transcript's own words, so a wrapped command is
  still seen.

Words are streamed, so no word list is held, and every word is used: there is
no cap a run could pad past. This is not a defence against paraphrase or
dilution by padding (docs/TRANSCRIPT_FLAGS.md).
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterator

_WORD = re.compile(r"\w+")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
B64_MIN = 16
B64_MAX = 65536
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "с": "c", "р": "p", "х": "x",
    "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "ґ": "r",
    "α": "a", "ο": "o", "ρ": "p", "ι": "i", "κ": "k", "ν": "v",
    "τ": "t", "υ": "u", "χ": "x", "ɡ": "g", "ı": "i",
})  # fmt: skip


def fold(text: str) -> str:
    """NFKC, case fold, drop format characters, map lookalikes."""
    text = unicodedata.normalize("NFKC", text).casefold()
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.translate(CONFUSABLES)


def _decoded(token: str) -> str | None:
    if len(token) < B64_MIN or len(token) * 3 // 4 > B64_MAX:
        return None
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in text)
    return fold(text) if text and printable == len(text) else None


def words(text: str) -> Iterator[str]:
    """Every normalised word of *text*, then the words of its decoded base64 tokens."""
    for match in _WORD.finditer(fold(text)):
        yield match.group(0)
    original = unicodedata.normalize("NFKC", text)
    for token in sorted({m.group(0).rstrip("=") for m in _B64.finditer(original)}):
        inner = _decoded(token)
        if inner is not None:
            yield from (m.group(0) for m in _WORD.finditer(inner))


__all__ = ["B64_MAX", "B64_MIN", "CONFUSABLES", "fold", "words"]
