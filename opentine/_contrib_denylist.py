"""A contributor's local deny-list for open run datasets (0.75).

The list is a UTF-8 text file kept on the contributor's machine: one term per
line (names, emails, hostnames, project names), ``#`` starts a comment. It is
read here and never written anywhere: not into a bundle, a record, an output
or a digest that could be matched against a guess.

Matching is on a normalised view of the text, each normalised character mapped
back to the original so a replacement removes exactly the matched span:

* NFKD, combining marks and format characters (zero-width joiners and spaces,
  soft hyphens) dropped, then ``casefold`` (``José``, ``JOSE``, ``jo​se``);
* a term keeps only its letters and digits, and up to four separators (any
  character that is not a letter or digit) may sit between any two of them, so
  ``Jane Doe`` also matches ``jane.doe``, ``JANE_DOE``, ``janedoe``,
  ``Jane ,  Doe`` and ``j-a-n-e d-o-e``.

Matches are over-inclusive on purpose (``acme`` inside ``acmeville``): a
false hit removes a few characters, a miss publishes a name. Strings shaped
like an object id (``run:sha256:<hex>``) are never rewritten or scanned, since
a short term can sit inside hex and the ids are content digests, not text; only
the five object kinds count as an id prefix, so ``name:sha256:<hex>`` is scanned.
Up to four separators may sit between letters, and common Cyrillic and Greek
look-alikes fold to Latin letters.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any

MIN_TERM = 3
MAX_TERMS = 10_000
MARK = "[REDACTED:contributor]"
_OID = re.compile(r"([a-z][a-z0-9_-]*):sha256:[0-9a-f]{64}")
_KINDS = frozenset({"blob", "event", "run", "attestation", "annotation"})
_SEP = r"[^0-9a-z]{0,4}"
#: Latin look-alikes from Cyrillic and Greek, applied after casefold (review 0.75).
_CONFUSABLE = str.maketrans(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u0501\u04bb\u04cf"
    "\u03bd\u03bf\u03b1\u03b5\u03b9\u03ba\u03c4\u03c1\u0432\u043d\u0442\u043c\u043a",
    "aeopcyxijsdhlvoaeiktpbhtmk",
)


class DenyListError(ValueError):
    pass


def _fold(ch: str) -> str:
    out = []
    for part in unicodedata.normalize("NFKD", ch):
        if unicodedata.category(part) in ("Mn", "Me", "Cf"):
            continue
        out.append(part.casefold().translate(_CONFUSABLE))
    return "".join(out)


def normalise(text: str) -> tuple[str, list[int]]:
    """``(normalised text, original index of each normalised character)``."""
    chars: list[str] = []
    where: list[int] = []
    for index, ch in enumerate(text):
        folded = _fold(ch)
        chars.append(folded)
        where.extend([index] * len(folded))
    return "".join(chars), where


def _letters(term: str) -> str:
    return "".join(ch for ch in normalise(term)[0] if ch.isalnum())


class DenyList:
    """Compiled terms; ``len()`` is the number of terms, the only thing ever reported."""

    def __init__(self, terms: list[str]) -> None:
        cores = sorted({_letters(t) for t in terms if _letters(t)}, key=lambda c: (-len(c), c))
        short = [c for c in cores if len(c) < MIN_TERM]
        if short:
            raise DenyListError(f"deny-list terms need at least {MIN_TERM} letters or digits")
        if not cores:
            raise DenyListError("the deny-list holds no terms")
        if len(cores) > MAX_TERMS:
            raise DenyListError(f"the deny-list holds more than {MAX_TERMS} terms")
        self._count = len(cores)
        alts = (
            "".join(re.escape(c) + _SEP for c in core[:-1]) + re.escape(core[-1]) for core in cores
        )
        self._re = re.compile("|".join(alts))

    def __len__(self) -> int:
        return self._count

    def __repr__(self) -> str:  # never the terms
        return f"DenyList(<{self._count} terms>)"

    def spans(self, text: str) -> list[tuple[int, int]]:
        """Original ``[start, end)`` spans of every match outside object ids."""
        flat, where = normalise(text)
        # Only a digest, and the prefix of a real object kind, is exempt: a
        # private name shaped like a prefix (``name:sha256:<hex>``) is not.
        exempt = [
            (o.start() if o.group(1) in _KINDS else o.end(1), o.end()) for o in _OID.finditer(text)
        ]
        out = []
        for found in self._re.finditer(flat):
            start, end = where[found.start()], where[found.end() - 1] + 1
            if any(a <= start < b for a, b in exempt):
                continue
            out.append((start, end))
        return out

    def scrub_text(self, text: str) -> tuple[str, int]:
        spans = self.spans(text)
        for start, end in reversed(spans):
            text = text[:start] + MARK + text[end:]
        return text, len(spans)

    def scrub_bytes(self, body: bytes) -> tuple[bytes, int]:
        try:
            text, encoding = body.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            text, encoding = body.decode("latin-1"), "latin-1"
        new, hits = self.scrub_text(text)
        return (new.encode(encoding) if hits else body), hits

    def scrub_value(self, value: Any) -> tuple[Any, int]:
        """A decoded JSON value with every key and string scrubbed."""
        if isinstance(value, str):
            return self.scrub_text(value)
        if isinstance(value, list):
            pairs = [self.scrub_value(v) for v in value]
            return [v for v, _ in pairs], sum(n for _, n in pairs)
        if isinstance(value, dict):
            out, hits = {}, 0
            for key, item in value.items():
                new_key, a = self.scrub_text(key)
                new_item, b = self.scrub_value(item)
                out[new_key], hits = new_item, hits + a + b
            return out, hits
        return value, 0

    def count(self, value: Any) -> int:
        """Matches left in *value* (bytes, text or a decoded JSON value)."""
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError:
                value = value.decode("latin-1")
        return self.scrub_value(value)[1]


def load(path: str | Path) -> DenyList:
    """Read a deny-list file; refuses a missing, empty or unreadable one (fail closed)."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise DenyListError(f"cannot read the deny-list: {exc.strerror or exc}") from None
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise DenyListError("the deny-list is not UTF-8") from None
    terms = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    return DenyList([t for t in terms if t])


__all__ = ["MARK", "MIN_TERM", "DenyList", "DenyListError", "load", "normalise"]
