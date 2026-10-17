"""Whether any word a redaction removed is still in its result, in linear time.

``_redact_json`` checks a decoded rescan against the spans the byte scan removes:
a removed word of four or more letters or digits still present means the rescan
is not trusted. Checking each span by itself re-blanked the scan labels in the
whole result and searched it once per span, so a JSON-escaped log with a header
on every line took minutes (O(spans x length)). Here the labels are blanked once
and every removed word is looked for in one pass: plain ``in`` while that is
cheap, else an Aho-Corasick automaton over the result's distinct word runs (a
removed word, being letters and digits only, can only occur inside one).

A stdlib-only leaf.
"""

from __future__ import annotations

import re
from collections import Counter, deque
from collections.abc import Iterable

#: A word of removed text the checks look for: a shorter run (a one-letter
#: ``MYSQL_PWD=x``) occurs in ordinary text by chance.
WORD = re.compile(rb"[A-Za-z0-9\x80-\xff]{4,}")
#: Scan labels are taken out first: "[REDACTED PRIVATE KEY]" leaves no "PRIVATE".
LABELS = re.compile(rb"\[REDACTED(?: PRIVATE KEY)?\]")
#: Below this many (words x result bytes), one C-level ``in`` per word is faster.
_DIRECT = 1 << 22


def _found_in(words: set[bytes], runs: Iterable[bytes]) -> bool:
    """Whether some run contains some word (Aho-Corasick; linear in both)."""
    goto: list[dict[int, int]] = [{}]
    final = [False]
    for word in words:
        node = 0
        for byte in word:
            child = goto[node].get(byte)
            if child is None:
                child = len(goto)
                goto[node][byte] = child
                goto.append({})
                final.append(False)
            node = child
        final[node] = True
    fail = [0] * len(goto)
    queue = deque(goto[0].values())
    while queue:
        node = queue.popleft()
        for byte, child in goto[node].items():
            queue.append(child)
            back = fail[node]
            while back and byte not in goto[back]:
                back = fail[back]
            fail[child] = goto[back].get(byte, 0)
            final[child] = final[child] or final[fail[child]]
    for run in runs:
        node = 0
        for byte in run:
            while node and byte not in goto[node]:
                node = fail[node]
            node = goto[node].get(byte, 0)
            if final[node]:
                return True
    return False


def any_left(words: set[bytes], after: bytes) -> bool:
    """Whether any of *words* occurs in *after* once its scan labels are blanked."""
    if not words:
        return False
    clean = LABELS.sub(b" ", after)
    if len(words) * len(clean) <= _DIRECT:
        return any(word in clean for word in words)
    runs = set(WORD.findall(clean))
    if not words.isdisjoint(runs):
        return True
    return _found_in(words, runs)


def more_words(result: bytes, bound: bytes) -> bool:
    """Whether *result* holds some word more often than *bound* (labels blanked).

    *bound* is the original string's own full redaction, every nesting level
    decoded; a word *result* keeps more often than that is text the full
    redaction removes, so *result* is not trusted. Linear: two word counts.
    """
    allowed = Counter(WORD.findall(LABELS.sub(b" ", bound)))
    have = Counter(WORD.findall(LABELS.sub(b" ", result)))
    return any(count > allowed[word] for word, count in have.items())


__all__ = ["LABELS", "WORD", "any_left", "more_words"]
