"""Survivor checks for ``_redact_json``: did a rescan keep a word the scan removes?

Split out of ``_redact_json`` for the module line cap. A rescan of decoded text
can stop early (it sees unescaped quotes) or run across an escaped ``\\n``; these
checks decide whether its result may stand or the whole string must be redacted.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from opentine._redact_edits import Step, changed
from opentine._redact_json_parse import decoded_offsets
from opentine._redact_survive import LABELS, WORD, any_left, more_words

#: Run separators for :func:`within`: whitespace, and the escapes a JSON string
#: literal held in a string spells its breaks and quotes with.
_RUNS = re.compile(rb'(?:\s|\\[nrtbf"\\/])+')


def text(token: bytes) -> bytes | None:
    try:
        return json.loads(token.decode("utf-8")).encode("utf-8", "surrogatepass")
    except (ValueError, UnicodeError, AttributeError):
        return None


def survives(original: bytes, result: bytes, steps: list[Step], fine: bytes | None) -> bool:
    """Whether text *original*'s own redaction (*fine*: every nested level decoded,
    None if clean) removes is still in *result*, at whatever depth it hid."""
    before, after = text(original), text(result)
    if before is None or after is None:  # tokens are validated strings; defensive
        return before is not None
    spans = changed(before, steps)
    removed = {word for low, high in spans for word in WORD.findall(before, low, high)}
    bound = before if fine is None else text(fine)
    return any_left(removed, after) or bound is None or more_words(after, bound)


def covers(token: bytes, base: int, fine: bytes, spans: list[tuple[int, int]]) -> bool:
    """Whether *fine* removes every word the byte scan's *spans* take out of *token*
    (a rescan sees unescaped quotes and can stop early; a span with no word of four
    is never trusted to it)."""
    offsets, plain, after = decoded_offsets(token), text(token), text(fine)
    if offsets is None or plain is None or after is None:
        return False
    last, removed = len(token) - 1, set()
    for start, end in spans:
        low, high = max(start - base, 1), min(end - base, last)
        if high <= low:
            continue
        while high < last and offsets[high] == offsets[high - 1]:
            high += 1  # past an escape the span cuts
        words = WORD.findall(plain, offsets[low], offsets[high])
        if not words:
            return False
        removed.update(words)
    return not any_left(removed, after)


def within(result: bytes | None, bound: bytes | None) -> bool:
    """Whether every non-space run of *result* occurs as often in *bound* (labels
    blanked): *result* shows nothing *bound* does not, short or symbol-only text
    included -- the check the four-character word rule cannot make."""
    if result is None or bound is None:
        return False
    allowed = Counter(filter(None, _RUNS.split(LABELS.sub(b" ", bound))))
    have = Counter(filter(None, _RUNS.split(LABELS.sub(b" ", result))))
    return all(count <= allowed[run] for run, count in have.items())


__all__ = ["covers", "survives", "text", "within"]
