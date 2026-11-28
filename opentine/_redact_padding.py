"""Padding of a base64 blob, told apart from an ``=`` after a credential name (0.88).

A signed note or checkpoint carries base64 lines; about one in 200 ends ``...pw=``
or ``...Pw==`` and read as a credential name with the rest of the note as its
value. Exempting every long, digit-bearing word before ``=`` leaked real
assignments (``PrimaryDatabase2Password= hunter2``), so a blob must also not
read as words: all capitals, or camel/digit segments (bar the last) with at
most one short or capital run (``Db``, ``AWS``); a run of 4+ capitals counts
twice. Random base64 has several short or all-capital runs.
"""

from __future__ import annotations

import re

#: A whole string of padded base64; its ``=`` assigns nothing.
PADDED_B64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={1,2}")
_TAIL = re.compile(r"(?:^|\s)([A-Za-z0-9+/]{20,})\Z")
_SEGMENT = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")


def _wordy(blob: str) -> bool:
    """``ProductionDatabaseUser1Password`` is words; random base64 has short runs."""
    if blob.isupper():  # GITHUBPERSONALACCESSTOKEN; random base64 mixes case
        return True
    segments = _SEGMENT.findall(blob)
    # Names hold an odd ``Db`` or ``AWS``; base64 has several short or capital runs.
    odd = sum(len(s) < 3 or s.isupper() for s in segments[:-1])
    odd += sum(len(s) >= 4 and s.isupper() for s in segments[:-1])
    return odd < 2


def padding_of_blob(label: str, candidate: str) -> bool:
    """``label=candidate`` is a base64 word ending ``label``, padded, then a break."""
    pad = 2 if candidate[:1] == "=" else 1
    rest = candidate[pad - 1 :]
    found = _TAIL.search(label)
    if found is None or (rest and not rest[0].isspace()):
        return False
    blob = found.group(1)
    if _wordy(blob):
        return False
    upper = sum(c.isupper() for c in blob)
    return any(c.isdigit() or c in "+/" for c in blob) or upper >= 6
