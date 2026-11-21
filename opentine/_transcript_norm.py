"""Text normalisation before transcript features (0.74, release 0.73.0).

A run that wants to stop clustering with known bad runs can change how its
text looks without changing what it does. Before features are taken the text
is normalised, so these spellings embed like the plain one:

* NFKC (full-width and compatibility forms fold to their plain letters);
* format characters (Unicode category ``Cf``: zero-width spaces and joiners,
  bidirectional controls) are dropped;
* after case folding, Cyrillic and Greek letters that look like Latin ones
  map to the Latin letter (``CONFUSABLES``, version 1);
* base64 runs of at least ``B64_MIN`` characters that decode to printable
  UTF-8 text have the decoded text appended (at most ``B64_MAX`` per text).

The rules are part of the hash backend's description, so changing them
changes its digest.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

B64_MIN = 16
B64_MAX = 64
RULES = "nfkc; drop Cf; casefold; confusables/1; base64/1"
_LOOK = {
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "α": "a", "β": "b",
    "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ω": "w", "ϲ": "c",
}  # fmt: skip
CONFUSABLES = str.maketrans(_LOOK)
_B64 = re.compile(rf"[A-Za-z0-9+/]{{{B64_MIN},}}={{0,2}}")


def _decoded(text: str) -> list[str]:
    out = []
    for match in _B64.finditer(text):
        token = match.group(0)
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            plain = raw.decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        if plain and sum(ch.isprintable() or ch.isspace() for ch in plain) >= 0.9 * len(plain):
            out.append(plain)
        if len(out) >= B64_MAX:
            break
    return out


def _fold(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.casefold().translate(CONFUSABLES)


def normalise(text: str) -> str:
    """*text* folded as above, followed by any base64 text it carries (folded too)."""
    folded = unicodedata.normalize("NFKC", text)
    folded = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    extra = [_fold(piece) for piece in _decoded(folded)]
    return "\n".join([folded.casefold().translate(CONFUSABLES), *extra])


__all__ = ["CONFUSABLES", "RULES", "normalise"]
