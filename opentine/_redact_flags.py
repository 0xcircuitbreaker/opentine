"""A secret passed as a separate argument: ``--password hunter2``, ``--token "x"``.

A stdlib-only leaf. Both ``--flag value`` and ``--flag=value`` are handled here.
It used to accept only a bare value (``[^\\s"'-][^\\s"']{0,511}``), so a
quoted secret -- ``helm repo add ... --password "x"``, ``oras login --password 'x'``,
``--client-secret "x"`` inside a shell tool call -- was written out verbatim, in
plain text and inside JSON (where the rule matched only the lone ``\\`` of the
``\\"`` escape). A quoted value is now redacted inside its quotes, which stay, by
the same end rule the quoted-field step uses (``_redact_fields``): backslash runs
honoured, and an escaped ``\\"value\\"`` never runs past the unescaped quote that
ends the JSON string holding it, so JSON stays JSON. A bare value is a run of whole
escape pairs with no bound, so a long JWT after ``--access-token`` is removed whole
rather than cut at 512 bytes with its tail left behind.
"""

from __future__ import annotations

import re

from opentine._redact_fields import value_end

Edit = tuple[int, int, bytes]
_QUOTES = (34, 39)  # " and '
_BACKSLASH = 92
# One or two dashes (``-token=x`` is how Go CLIs such as consul and nomad spell it),
# then a space or ``=``: ``_NAME`` leaves bare ``token``/``pass`` out to keep
# counters, so ``--token=x`` and ``--pass=x`` matched no assignment and were kept.
# A flag right after a literal ``\\n``/``\\t`` escape (a repr, a log of a
# command string) counts too.
_HEAD = re.compile(
    rb"(?i)(?:(?<![A-Za-z0-9_-])|(?<=\\[nrt]))-{1,2}(?:password|passwd|pass|token|"
    rb"api[_-]?key|secret|client[_-]?secret|auth[_-]?token|access[_-]?token)(?:[ \t]+|=)"
)
# Whole escape pairs, never a raw quote: a value ending in the ``\\`` of a JSON
# ``\\"`` would take the backslash and leave a raw quote behind.
_BARE = re.compile(rb"(?:[^\s\"'\\-]|\\[^\s\"'])(?:[^\s\"'\\]|\\[^\s\"'])*")


def _escaped_end(value: bytes, begin: int, depth: int, quote: int) -> tuple[int, int]:
    """End of a value quoted by *depth* backslashes and *quote* (JSON nested *depth*/2 deep).

    ``\\"`` quotes a value inside one JSON string; ``\\\\\\"`` inside a JSON string
    held by another (``{"out": "{\\"command\\": \\"--token \\\\\\"x\\\\\\"\\"}"}``).
    The value closes at the same run and quote; a quote behind a *shorter* run (or
    a raw one) closes a string that contains it, so the value stops before that
    run and the document keeps its structure. A longer run is a literal quote
    inside the value.
    """
    index = begin
    while index < len(value) and value[index] not in (10, 13):
        byte = value[index]
        if byte == _BACKSLASH:
            run = index
            while run < len(value) and value[run] == _BACKSLASH:
                run += 1
            if run < len(value) and value[run] in _QUOTES and run - index <= depth:
                closes = run - index == depth and value[run] == quote
                if closes or run - index < depth:
                    return index, run + 1 if closes else index
            index = run + 1 if run < len(value) and value[run] in _QUOTES else run
            continue
        if byte in _QUOTES:
            return index, index
        index += 1
    return index, index


def flag_edits(value: bytes) -> list[Edit]:
    """The edits that redact every credential flag's value in *value*."""
    edits: list[Edit] = []
    cursor = 0
    while match := _HEAD.search(value, cursor):
        start = cursor = match.end()
        first = value[start] if start < len(value) else None
        depth = 0
        while start + depth < len(value) and value[start + depth] == _BACKSLASH:
            depth += 1
        if depth and start + depth < len(value) and value[start + depth] in _QUOTES:
            begin = start + depth + 1
            end, resume = _escaped_end(value, begin, depth, value[start + depth])
        elif first in _QUOTES:
            begin = start + 1
            end, resume = value_end(value, begin, first, False)
        else:
            bare = _BARE.match(value, start)
            if bare is None:
                continue
            begin, end, resume = start, bare.end(), bare.end()
        if end > begin:
            edits.append((begin, end, b"[REDACTED]"))
        cursor = max(cursor, resume, end)
    return edits


__all__ = ["flag_edits"]
