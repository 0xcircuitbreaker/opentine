"""Whether every one of many strings occurs in one text, in linear time.

The import checks a span's 1.36 turns against its classic payload text. One
``in`` per turn costs up to the whole text each, so ten thousand turns against a
megabytes-long payload took minutes of CPU per span (O(turns x length)). Here
each distinct needle is first tried with C-level ``in`` while the summed worst
case stays within a few passes over the text; past that budget the rest are
found together by one Aho-Corasick pass, linear in the text plus the needles.

A trie costs about a hundred bytes per needle character, so the automaton is only
built for a bounded remainder: past it the answer is "not proven" (``False``),
which every caller treats as "keep both", never as a reason to drop content.

A stdlib-only leaf.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable

#: Direct ``in`` checks allowed before switching: this many passes over the text.
_DIRECT_PASSES = 32
#: Needle characters the fallback automaton may hold (its memory is ~100x this).
_TRIE_CHARS = 1 << 16


def _all_found(needles: set[str], text: str) -> bool:
    """Aho-Corasick: whether every needle occurs in *text* (linear in both)."""
    goto: list[dict[str, int]] = [{}]
    ends = [False]
    for needle in needles:
        node = 0
        for char in needle:
            child = goto[node].get(char)
            if child is None:
                child = len(goto)
                goto[node][char] = child
                goto.append({})
                ends.append(False)
            node = child
        ends[node] = True
    fail = [0] * len(goto)
    queue = deque(goto[0].values())
    while queue:
        node = queue.popleft()
        for char, child in goto[node].items():
            queue.append(child)
            back = fail[node]
            while back and char not in goto[back]:
                back = fail[back]
            fail[child] = goto[back].get(char, 0)
    # A state's suffix chain is walked once in all: when a state is reached that
    # was seen before, every state behind it on the chain was seen with it.
    seen = [False] * len(goto)
    missing = len(needles)
    node = 0
    for char in text:
        while node and char not in goto[node]:
            node = fail[node]
        node = goto[node].get(char, 0)
        state = node
        while state and not seen[state]:
            seen[state] = True
            if ends[state]:
                missing -= 1
                if not missing:
                    return True
            state = fail[state]
    return False


def all_in(needles: Iterable[str], text: str) -> bool:
    """Whether every string in *needles* is provably a substring of *text*.

    Bounded in time and memory: ``False`` means "absent, or not proven within
    the work budget".
    """
    remaining = {needle for needle in needles if needle}
    if any(len(needle) > len(text) for needle in remaining):
        return False
    budget = _DIRECT_PASSES * (len(text) + 1)
    for needle in sorted(remaining, key=len):
        if budget <= 0:
            break
        budget -= len(text) + len(needle)
        if needle not in text:
            return False
        remaining.discard(needle)
    if not remaining:
        return True
    if sum(map(len, remaining)) > _TRIE_CHARS:
        return False
    return _all_found(remaining, text)


__all__ = ["all_in"]
