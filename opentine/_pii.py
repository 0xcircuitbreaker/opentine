"""PII detectors for the ``opentine-redaction/3`` ruleset (0.46).

``opentine-redaction/2`` removes credentials. ``/3`` is that ruleset plus the
personal data below, each found by a pattern and confirmed by a validator
(:mod:`opentine._pii_ids`), then an optional local classifier layer
(:mod:`opentine._pii_classify`) for what no pattern can see (names, dates of
birth). Detection never leaves the process: there is no remote classifier.

Write-side redaction is unchanged (secrets only, ``/2``): PII is detected and
redacted where the caller asks for it -- ``tine redact check --pii`` (a version
2 redaction report) and the hybrid search embedding index, which embeds only
text that has been through :func:`redact_text`.

:func:`find` returns spans, never stores them; a report names detector kinds and
object ids only, so it cannot leak the value it found.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from opentine import _pii_ids as ids

PII_RULESET = "opentine-redaction/3"
#: A plug-in classifier's kind must be a report name; anything else is reported as ``other``.
_KIND = re.compile(r"[a-z0-9_-]{1,32}")
_STREET = (
    r"Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl"
    r"|Terrace|Parkway|Pkwy|Highway|Hwy|Square|Sq|Close|Crescent"
)

#: (kind, pattern, validator), in priority order: an earlier detector's span wins
#: an overlap, so a Luhn-valid card is never also reported as a phone number.
DETECTORS: tuple[tuple[str, re.Pattern[str], Callable[[str], bool]], ...] = (
    ("email", re.compile(
        r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*"
        r"\.[A-Za-z]{2,24}(?![\w-])"), ids.email),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), ids.iban),
    ("card", re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])"), ids.card),
    ("gov-id:us-ssn", re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])"), ids.us_ssn),
    ("gov-id:uk-nino", re.compile(r"\b[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"), ids.uk_nino),
    ("gov-id:es-dni", re.compile(r"\b[XYZ\d]\d{7}-?[A-Z]\b"), ids.es_dni),
    ("phone", re.compile(
        r"(?<![\w+])(?:\+\d{1,3}[ .-]?|1[ .-])?(?:\(\d{2,4}\)[ .-]?)?\d{2,4}(?:[ .-]\d{2,6}){1,4}"
        r"(?![\w-])"), ids.phone),
    ("address", re.compile(
        r"\b\d{1,6}\s+(?:[A-Z][a-z]+\.?\s+){1,4}(?:" + _STREET + r")\b\.?"
        r"(?:,?\s+(?:Apt|Suite|Unit|#)\.?\s*\w+)?"
        r"(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?"),
     lambda _: True),
    ("address", re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]? \d[ABD-HJLNP-UW-Z]{2}\b"), lambda _: True),
)  # fmt: skip
KINDS: tuple[str, ...] = tuple(dict.fromkeys(kind for kind, _, _ in DETECTORS))


@dataclass(frozen=True, order=True)
class Hit:
    start: int
    end: int
    kind: str


def _place(hits: list[Hit], taken: list[tuple[int, int]], hit: Hit) -> None:
    if any(hit.start < end and start < hit.end for start, end in taken):
        return
    taken.append((hit.start, hit.end))
    hits.append(hit)


def find(text: str, classifier: Any = None) -> list[Hit]:
    """Every validated PII span in *text*, sorted, non-overlapping."""
    hits: list[Hit] = []
    taken: list[tuple[int, int]] = []
    for kind, pattern, valid in DETECTORS:
        for match in pattern.finditer(text):
            if valid(match.group(0)):
                _place(hits, taken, Hit(match.start(), match.end(), kind))
    if classifier is not None:
        for start, end, kind in classifier.classify(text):
            if type(start) is int and type(end) is int and 0 <= start < end <= len(text):
                label = kind if isinstance(kind, str) and _KIND.fullmatch(kind) else "other"
                _place(hits, taken, Hit(start, end, f"classifier:{label}"))
    return sorted(hits)


def redact_text(text: str, classifier: Any = None) -> tuple[str, Counter[str]]:
    """*text* with each PII span replaced by ``[REDACTED:<kind>]``, and the counts."""
    out: list[str] = []
    counts: Counter[str] = Counter()
    cursor = 0
    for hit in find(text, classifier):
        out += [text[cursor : hit.start], f"[REDACTED:{hit.kind}]"]
        counts[hit.kind] += 1
        cursor = hit.end
    out.append(text[cursor:])
    return "".join(out), counts


def detectors_in(data: bytes, classifier: Any = None) -> set[str]:
    """The PII kinds present in *data* (decoded as UTF-8, invalid bytes replaced)."""
    return {hit.kind for hit in find(data.decode("utf-8", "replace"), classifier)}


__all__ = ["DETECTORS", "KINDS", "PII_RULESET", "Hit", "detectors_in", "find", "redact_text"]
