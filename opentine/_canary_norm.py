"""Fold text so a mutated copy of a canary or holdout item still matches (0.60 review).

A copier that wants to dodge a byte-exact search changes letter case, inserts
or removes whitespace, adds zero-width characters, or swaps letters for
lookalikes from another script. :func:`fold` undoes those: Unicode NFKC,
case folding, a fixed table of Cyrillic and Greek lookalikes mapped to the
Latin letter they imitate, and every whitespace and format (``Cf``) character
dropped. It is applied to both sides of a comparison, so it only ever adds
matches. Splitting one canary across several objects is not undone here.
"""

from __future__ import annotations

import unicodedata

VERSION = "fold-1"
_LOOKALIKE = {
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j", "һ": "h",
    "ӏ": "l", "ԁ": "d", "ԛ": "q", "ԝ": "w", "α": "a", "ε": "e", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
}  # fmt: skip


def fold(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).casefold()
    out = []
    for ch in text:
        if ch.isspace() or unicodedata.category(ch) == "Cf":
            continue
        out.append(_LOOKALIKE.get(ch, ch))
    return "".join(out)


def fold_words(text: str) -> str:
    """:func:`fold` that keeps whitespace, for word shingles."""
    text = unicodedata.normalize("NFKC", text).casefold()
    return "".join(_LOOKALIKE.get(ch, ch) for ch in text if unicodedata.category(ch) != "Cf")


__all__ = ["VERSION", "fold", "fold_words"]
