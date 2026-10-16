"""Decoration a tool puts around each line of a key it prints.

``cat -n`` numbers, ``grep -n`` prefixes, comment leaders, diff markers, quotes,
table borders and terminal colours: stripped before a line is tested for key
material, by the line masker and the in-string extent alike.
"""

from __future__ import annotations

import re

DATA = re.compile(r"=?[A-Za-z0-9+/]{4,}={0,2}")
#: RFC 1421 / OpenPGP / RFC 4716 headers and PuTTY key-file fields between a
#: marker and the body (open blocks only).
HEADER = re.compile(
    r"(?i)(?:proc-type|dek-info|version|comment|hash|charset|subject|x-[a-z0-9-]{1,64}"
    r"|encryption|public-lines|private-lines|key-derivation|argon2-[a-z]{1,32}):"
)
#: What a tool puts in front of each line it prints: ``cat -n``/``nl`` numbers,
#: ``grep -n``'s ``path:N:``, markdown quotes and bullets. Stripped only inside
#: an open block, before the key-material test (audit 0.10 re-audit #18).
_PREFIX = re.compile(r"^\s*(?:[^\s:]{1,256}:\d+[:-])?\s*\d*[\s:|]*(?:>\s*)*(?:[-*+]\s+)?")
#: Decoration around a body line: a diff's ``-``/``+``, quotes, ``cat -A``'s
#: ``$``, a source literal's ``\\n" +`` (final pass, #9). Stripped with plain
#: str methods: no regex backtracking over a long line.
_HEAD_DECOR = "-+ \t\"'`|>#;%*\u2502\u2503\u2551\u2506\u2507\u250a\u250b\u254e\u254f\u00a6"
_TAIL_DECOR = " \t\"'`$,;+)\\|\u2502\u2503\u2551\u2506\u2507\u250a\u250b\u254e\u254f\u00a6"
#: Terminal colour and cursor sequences (``grep --color=always``, ``bat``), and
#: a bounded OSC: removed before the key-material test (final pass 5, #9).
_ANSI = re.compile(r"\x1b\[[0-?]{0,32}[ -/]{0,8}[@-~]|\x1b\][^\x07\x1b]{0,256}(?:\x07|\x1b\\)")


def _decor(text: str) -> str:
    """*text* without leading decoration: comment leaders, quotes, bullets, borders.

    A ``# ``-, ``// ``- or ``; ``-commented key (a config or source file the agent
    printed) closed the block on its first body line, which was then saved
    verbatim (final pass 5, #9). ``//`` counts only before whitespace: ``/`` is
    a base64 character.
    """
    while True:
        text = text.lstrip(_HEAD_DECOR)
        if text.startswith("//") and (len(text) == 2 or text[2] in " \t"):
            text = text[2:]
            continue
        return text


def key_body(line: str) -> str:
    """*line* without its tool prefix and decoration: one backward pass, one slice.

    Trimming a trailing ``\\n`` escape by re-slicing copied the whole line per
    escape, quadratic in the line: one 1 MB line in an open block cost ~25 s of
    synchronous CPU (final pass 2, #8).
    """
    stripped = _decor(_PREFIX.sub("", _decor(_ANSI.sub("", line)), count=1))
    end = len(stripped)
    while end:
        if stripped[end - 1] in _TAIL_DECOR:
            end -= 1
        elif end >= 2 and stripped[end - 2] == "\\" and stripped[end - 1] in "nr":
            end -= 2
        else:
            break
    return stripped[:end]


__all__ = ["DATA", "HEADER", "key_body"]
