"""Redaction as edits: what each scan step replaces, before it is applied.

A stdlib-only leaf. The byte scan (``redaction._scan``) is an ordered list of
steps; each step returns the non-overlapping ``(start, end, replacement)`` edits
it makes on a value, exactly what ``re.sub`` would. :func:`run` applies them in
order -- that *is* the scan. :func:`changed` runs every step alone on one value
and reports where a step would remove anything, which is what lets the JSON path
(``_redact_json``) redact whole strings around those places instead of letting a
byte regex eat a quote or a separator.
"""

from __future__ import annotations

import re
from collections.abc import Callable

Edit = tuple[int, int, bytes]
Step = Callable[[bytes], list[Edit]]
#: Bytes a scan may swallow beside a value without removing anything secret.
_STRUCTURAL = b"\\\"' \t\r\n"


def _char_end(value: bytes, end: int, limit: int) -> int:
    """*end* moved past UTF-8 continuation bytes, so an edit never splits a character.

    A bounded value run (``{1,512}``) can stop inside a multi-byte character, which
    left its continuation bytes behind the replacement: valid UTF-8 in, invalid out,
    and ``redact_text`` raised ``UnicodeDecodeError`` from inside ``Run.save``.
    """
    while end < limit and 0x80 <= value[end] <= 0xBF:
        end += 1
    return end


def sub_step(
    pattern: re.Pattern[bytes],
    repl: bytes | Callable[[re.Match[bytes]], bytes],
    tail: Callable[[re.Match[bytes]], re.Pattern[bytes] | None] | None = None,
) -> Step:
    """The edits ``pattern.sub(repl, value)`` makes (``repl`` bytes is literal).

    *tail*, for a pattern whose value is a bounded run, names the run class that
    continues it: an edit is extended over that class (up to the next match), so a
    value longer than its bound is removed whole instead of cut where it fell.
    """

    def step(value: bytes) -> list[Edit]:
        matches = list(pattern.finditer(value))
        edits: list[Edit] = []
        for index, match in enumerate(matches):
            limit = matches[index + 1].start() if index + 1 < len(matches) else len(value)
            replacement = repl(match) if callable(repl) else repl
            # A step that keeps its match (a prose exemption) changes nothing to cut.
            kept = replacement == match.group(0)
            end = match.end()
            if not kept:
                rest = tail(match) if tail is not None else None
                if rest is not None:
                    # endpos=limit: never scan past the next match (else O(matches x n)).
                    end = rest.match(value, end, limit).end()
                end = _char_end(value, end, limit)
            edits.append((match.start(), end, replacement))
        return edits

    return step


def apply(value: bytes, edits: list[Edit]) -> bytes:
    if not edits:
        return value
    output = bytearray()
    cursor = 0
    for start, end, replacement in edits:
        output += value[cursor:start]
        output += replacement
        cursor = end
    output += value[cursor:]
    return bytes(output)


def run(value: bytes, steps: list[Step]) -> bytes:
    for step in steps:
        value = apply(value, step(value))
    return value


def _trimmed(old: bytes, new: bytes) -> tuple[int, int]:
    """Offsets in *old* of the bytes *new* does not keep (common ends trimmed)."""
    limit = min(len(old), len(new))
    prefix = 0
    while prefix < limit and old[prefix] == new[prefix]:
        prefix += 1
    suffix = 0
    while suffix < limit - prefix and old[-1 - suffix] == new[-1 - suffix]:
        suffix += 1
    return prefix, len(old) - suffix


def changed(value: bytes, steps: list[Step]) -> list[tuple[int, int]]:
    """Sorted spans of *value* some step, run alone, would remove.

    A span whose removed bytes are purely structural (a lone ``\\`` the scan
    swallowed beside a value, a quote, whitespace) is dropped: counting it would
    redact a string the scan only reformatted. Anything else counts, punctuation
    included -- a password may be all symbols (``!@#$%^&*``). When trimming the
    ends the removed bytes share with the label leaves nothing (``password=]``),
    the whole match counts, so a value cannot hide inside the label's own bytes.
    """
    spans: list[tuple[int, int]] = []
    for step in steps:
        for start, end, replacement in step(value):
            old = value[start:end]
            if old == replacement:
                continue
            low, high = _trimmed(old, replacement)
            if high <= low:
                low, high = 0, len(old)
            if old[low:high].strip(_STRUCTURAL):
                spans.append((start + low, start + high))
    spans.sort()
    return spans


__all__ = ["Edit", "Step", "apply", "changed", "run", "sub_step"]
