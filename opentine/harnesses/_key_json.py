"""Private keys streamed across a CLI's JSON delta events.

A streaming CLI (gemini, hermes, qwen-code, claude ``--include-partial-messages``)
prints a model's answer as one JSON event per text delta. A key the model printed
then spans several events: ``BEGIN`` in one, the body and ``END`` in the next.
Masking each event alone replaced ``BEGIN``..end-of-string in the first and
returned the rest unchanged -- the joined text and the raw output kept the body
with no marker left for the record's scrubber to anchor on (final pass 3, #5).

:class:`JsonKeys` follows the string *path* that opened the block (``content``,
``event.delta.text``) into the following events: each string there is masked
whole until the one holding ``END``. A marker split between two deltas
(``-----BEG`` + ``IN RSA PRIVATE KEY-----``) is found through a short carry of the
previous event's string at the same path.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from opentine.harnesses._key_b64 import wrapped_key
from opentine.harnesses._key_extent import (
    MAX_OPEN_CHARS,
    anchor,
    b64_body_end,
    continued,
    delta_like,
    key_end,
    masked_text,
    open_after,
)
from opentine.harnesses._key_patterns import END, PLACEHOLDER

_CARRY = 160  # longer than any marker the patterns accept
_MAX_PATHS = 256
#: The rest of a ``BEGIN`` marker whose first dashes ended the previous delta.
_SPLIT_BEGIN = re.compile(r"-{0,4}BEGIN [A-Z ]{0,64}PRIVATE KEY(?: BLOCK)?-{1,5}")
#: A marker read across deltas whose dashes may sit in a delta that showed no
#: marker of its own and so was never carried (``…key:\n--`` + ``---BEGIN …``).
_LENIENT = re.compile(r"-{0,5}BEGIN [A-Z ]{0,64}PRIVATE KEY(?: BLOCK)?-{1,5}")
#: A string that may end inside a marker (``-----B``, ``-----BEGIN RSA ``): the
#: next event must be decoded even if it shows no dashes of its own.
_PARTIAL = re.compile(r"-{1,5}[A-Z ]{0,90}$")

Path = tuple[object, ...]


def walk_strings(
    event: object,
    fix: Callable[[Path, str], str],
    key_fix: Callable[[str], str] = masked_text,
) -> object:
    """*event* with *fix(path, string)* applied to every string value and *key_fix*
    to every key. List indices in a path read as ``#``. Iterative."""
    root = [event]
    stack: list[tuple[object, Path]] = [(root, ())]
    while stack:
        node, path = stack.pop()
        if isinstance(node, dict):
            # Keys too: a key block used as an object key stayed verbatim (round 4, #5).
            items = [(key_fix(k) if isinstance(k, str) else k, v) for k, v in node.items()]
            node.clear()
            node.update(items)
        entries = node.items() if isinstance(node, dict) else enumerate(node)  # type: ignore[union-attr]
        for key, value in list(entries):
            step = "#" if isinstance(node, list) else key
            child = path + (step,) if node is not root else ()
            if isinstance(value, str):
                node[key] = fix(child, value)  # type: ignore[index]
            elif isinstance(value, (dict, list)):
                stack.append((value, child))
    return root[0]


class JsonKeys:
    """Key-block state carried from one streamed delta event to the next."""

    def __init__(self) -> None:
        self.path: Path | None = None  # the string path inside an open block
        #: The path inside a base64-wrapped key streamed as deltas (final pass 6, #8).
        self.b64: Path | None = None
        self._anchor: tuple[object, ...] = ()
        self._spent = 0  # masked delta text carried by the open block so far
        self._carry: dict[Path, str] = {}
        self._line = 0
        self._carry_line = -2
        self._pending = False
        self.changed = False  # whether the last masked event differs from its input
        #: The last event left a key running to the end of a string: raw text
        #: lines after it are still key until prose (whole events never carry).
        self.raw_open = False

    @property
    def open(self) -> bool:
        return self.path is not None

    def wants(self, line: str) -> bool:
        """Whether *line* must be decoded. Every JSON event is: a marker split over
        three deltas (``…--`` + ``---BE`` + ``GIN …``) shows no marker text in the
        middle one, and skipping it broke the carry that joins them."""
        return line.lstrip().startswith(("{", "["))

    def tick(self) -> None:
        self._line += 1

    def _close(self) -> None:
        self.path = self.b64 = None
        self._spent = 0

    def mask(self, event: object) -> object:
        """*event* with every key span masked, following a block a delta opened."""
        delta, here = delta_like(event), anchor(event)
        if not delta or here != self._anchor or self._spent > MAX_OPEN_CHARS:
            self._close()  # a whole event, another message, or too long: no carry
        fresh = delta and self._carry_line == self._line - 1
        carry = self._carry if fresh else {}
        self._carry = {}
        opened: list[Path] = []
        closed = False
        b64_opened: list[Path] = []
        b64_closed = False
        self.changed = False

        def key_fix(key: str) -> str:
            masked = masked_text(key)
            self.changed = self.changed or masked != key
            return masked

        def fix(path: Path, text: str) -> str:
            masked = _fix(path, text)
            self.changed = self.changed or masked != text
            return masked

        def _fix(path: Path, text: str) -> str:
            nonlocal b64_closed
            tail = carry.get(path, "")
            if self.b64 is not None and path == self.b64:
                # Inside a base64-wrapped key: mask body deltas until prose.
                self._carry[path] = ""
                end = b64_body_end(text)
                if end == len(text):
                    self._spent += len(text)
                    return PLACEHOLDER if text.strip() else text
                b64_closed = True
                return (PLACEHOLDER if text[:end].strip() else text[:end]) + _pem(
                    path, text[end:], ""
                )
            found = wrapped_key(tail + text)
            if found is not None:
                start, whole = found
                self._carry[path] = ""
                if not whole:
                    b64_opened.append(path)
                cut = start - len(tail)
                return (masked_text(text[:cut]) if cut > 0 else "") + PLACEHOLDER
            return _pem(path, text, tail)

        def _pem(path: Path, text: str, tail: str) -> str:
            nonlocal closed
            if len(self._carry) < _MAX_PATHS and path not in self._carry:
                self._carry[path] = (tail + text)[-_CARRY:]
            if self.path is not None and path == self.path:
                end = END.search(tail + text)
                stop = max(0, end.end() - len(tail)) if end else continued(text)
                if end is None and stop == len(text):
                    self._spent += len(text)
                    return PLACEHOLDER if text.strip() else text
                closed = True  # END, or prose: the key ended inside this delta
                return _rest(path, text, stop, PLACEHOLDER if text[:stop].strip() else "")
            joined = tail + text
            split = next(
                (m for m in _LENIENT.finditer(joined) if m.start() < len(tail) < m.end()), None
            )
            if split is None and (opener := _SPLIT_BEGIN.match(text)):
                split_end = opener.end()
            elif split is not None:
                split_end = split.end() - len(tail)
            else:
                if open_after(text):
                    opened.append(path)
                return masked_text(text)
            # The marker started in the previous delta: mask its rest and the key.
            end = END.search(joined, split_end + len(tail))
            stop = max(0, end.end() - len(tail)) if end else key_end(text, split_end)
            if end is None and stop == len(text):
                opened.append(path)
                return PLACEHOLDER
            return _rest(path, text, stop, PLACEHOLDER)

        def _rest(path: Path, text: str, stop: int, label: str) -> str:
            rest = text[stop:]
            if open_after(rest):
                opened.append(path)
            return label + masked_text(rest)

        result = walk_strings(event, fix, key_fix)
        self.raw_open = bool(opened)
        self._carry_line = self._line
        self._pending = any(_PARTIAL.search(tail) for tail in self._carry.values())
        if opened and delta:
            self.path, self._anchor, self._spent = opened[-1], here, 0
        elif closed or opened:
            self.path = None
        if b64_opened and delta:
            self.b64, self._anchor = b64_opened[-1], here
        elif b64_closed or b64_opened:
            self.b64 = None
        return result


__all__ = ["JsonKeys", "masked_text", "open_after", "walk_strings"]
