"""``json.loads`` for untrusted text, refusing deep nesting before the C decoder sees it.

CPython's C JSON decoder recurses once per ``[`` / ``{`` and its recursion guard
sits above what a 1 MiB thread stack (Windows, worker threads) can hold, so a
hostile ``[[[[...`` overflows the C stack and kills the interpreter with no
traceback. :func:`loads` counts nesting with an iterative scan first and raises
:class:`ValueError` past :data:`MAX_NESTING`.
"""

from __future__ import annotations

import json
import re
from typing import Any

MAX_NESTING = 200
_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"?|[\[\]{}]')


def nesting(text: str) -> int:
    """The deepest ``[``/``{`` nesting in *text*, ignoring brackets inside strings."""
    depth = best = 0
    for match in _TOKEN.finditer(text):
        ch = match.group()[0]
        if ch in "[{":
            depth += 1
            best = max(best, depth)
        elif ch in "]}":
            depth -= 1
    return best


def loads(text: str | bytes, limit: int = MAX_NESTING, **kwargs: Any) -> Any:
    """:func:`json.loads` (with *kwargs*), or :class:`ValueError` past *limit* nesting."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8")
    if nesting(text) > limit:
        raise ValueError(f"JSON nested deeper than {limit}")
    return json.loads(text, **kwargs)


__all__ = ["MAX_NESTING", "loads", "nesting"]
