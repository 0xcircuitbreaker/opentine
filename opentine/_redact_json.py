"""Redact a JSON blob without weakening the byte scan or breaking the JSON.

The byte scan (``redaction._scan``) is authoritative: it is what 0.9 shipped, and
it sees credentials split across strings (``{"name": "X-Api-Key", "value": ...}``,
``["Cookie", "sid=..."]``, ``"password": "..."``). Its output is kept whenever it
still has the document's structure, which is nearly always. A byte regex cannot
see where a JSON string ends, though, so on a few shapes the scan eats the ``\\``
of an escaped quote or the ``","`` between members. Then the output is rebuilt
from the original bytes instead:

* every step of the scan is run alone over the document and reports the spans it
  would remove (``_redact_edits.changed``); any string, number or literal those
  spans touch is replaced *whole*: by its own scan as decoded text only when no
  word the spans remove survives in that, else by ``"[REDACTED]"``;
* the rebuilt document is checked the same way, up to three rounds, so no span
  any step would remove is left inside a token: nothing the scan would take out
  survives, and every untouched byte (numbers, escapes, layout) is the original's.

A whole string can go where the scan would have cut part of it -- precision traded
for validity in the rare broken case. A string with an escape is also scanned as
decoded text (a multi-line ``.netrc``, a JSON document held in a string), checked
against the original string's full redaction at every nested level. Names that
redact alike stay distinct (``#2``); a byte-order mark is kept.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from opentine._redact_checks import covers as _covers
from opentine._redact_checks import survives as _survives
from opentine._redact_checks import text as _text
from opentine._redact_checks import within
from opentine._redact_edits import Step, changed
from opentine._redact_json_parse import Token, parse_blob, shape

Scan = Callable[[bytes], bytes]

#: Larger blobs, and blobs that are not JSON, keep the byte scan's output as is.
MAX_REPAIR_BYTES = 32 * 1024 * 1024
_REDACTED = b'"[REDACTED]"'
#: JSON documents held inside strings are walked this many levels deep.
_NESTED = 3
_ROUNDS = 3
_BOM = b"\xef\xbb\xbf"
#: Every scan rule anchors on an ASCII letter (a name, a marker, a token prefix),
#: so decoded text without one is clean at every depth and costs no rescan.
_LETTER = re.compile(rb"[A-Za-z]")


def _decoded(token: bytes, scan: Scan, steps: list[Step], depth: int) -> bytes | None:
    """*token* rewritten from its own decoded text's redaction, or None if clean."""
    try:
        text = json.loads(token.decode("utf-8"))
        data = text.encode("utf-8", "surrogatepass")
    except (ValueError, UnicodeError):
        return _REDACTED
    if not _LETTER.search(data):
        return None
    clean = redact_json(data, scan, steps, depth + 1) if depth < _NESTED else scan(data)
    if clean == data:
        return None
    try:
        new = clean.decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        return _REDACTED
    lone = any(0xD800 <= ord(char) <= 0xDFFF for char in new)
    return json.dumps(new, ensure_ascii=lone).encode("utf-8")


def _touched(tokens: list[Token], spans: list[tuple[int, int]]) -> dict[int, list[tuple[int, int]]]:
    """Value tokens some span overlaps, each with those spans (spans sorted by start).

    One forward sweep with an active list; each step's edits never overlap, so
    that list stays as short as the step list.
    """
    hit: dict[int, list[tuple[int, int]]] = {}
    cursor, active = 0, []
    for index, (kind, start, end, _) in enumerate(tokens):
        while cursor < len(spans) and spans[cursor][0] < end:
            active.append(spans[cursor])
            cursor += 1
        if active:
            active = [span for span in active if span[1] > start]
            if kind in "sn" and active:
                hit[index] = active
    return hit


def _rebuild(data: bytes, tokens: list[Token], picks: dict[int, bytes]) -> bytes:
    owners = {tokens[i][3] for i in picks if tokens[i][3] >= 0}
    names: dict[int, set[bytes]] = {owner: set() for owner in owners}
    for index, (_, start, end, owner) in enumerate(tokens):
        if owner in owners and index not in picks:
            names[owner].add(data[start:end])
    # Where each (object, name) left off numbering, so k names that redact alike
    # cost k renames, not k^2 membership probes from "#2" every time.
    following: dict[tuple[int, bytes], int] = {}
    output, cursor = bytearray(), 0
    for index in sorted(picks):
        _, start, end, owner = tokens[index]
        name = base = picks[index]
        if owner >= 0:
            suffix = following.get((owner, base), 2)
            while name in names[owner]:
                name, suffix = base[:-1] + b"#%d" % suffix + b'"', suffix + 1
            following[(owner, base)] = suffix
            names[owner].add(name)
        output += data[cursor:start]
        output += name
        cursor = end
    output += data[cursor:]
    return bytes(output)


def _collisions(data: bytes, tokens: list[Token]) -> int:
    """How many member names repeat a sibling's (a scan can make two names alike)."""
    seen = {(owner, data[start:end]) for _, start, end, owner in tokens if owner >= 0}
    return sum(owner >= 0 for *_, owner in tokens) - len(seen)


def _redacted(token: bytes) -> bool:
    return token == _REDACTED or token.startswith(b'"[REDACTED]#')


def _splice(raw: bytes, tokens: list[Token], scan: Scan, steps: list[Step], depth: int) -> bytes:
    spans = changed(raw, steps)
    hit = _touched(tokens, spans)
    picks: dict[int, bytes] = {}
    for index, (kind, start, end, _) in enumerate(tokens):
        # Without an escape a string's bytes are its text, which the spans above
        # already cover; only a hit or escaped string needs its own decoded scan.
        token = raw[start:end]
        needed = kind == "s" and (index in hit or b"\\" in token)
        fine = _decoded(token, scan, steps, depth) if needed else None
        if index in hit:
            keep = fine is not None and _covers(token, start, fine, hit[index])
            picks[index] = fine if keep and fine is not None else _REDACTED
        elif fine is not None:
            picks[index] = fine
    result = _rebuild(raw, tokens, picks)
    for _ in range(_ROUNDS):
        current = parse_blob(result)
        if current is None:  # cannot happen: only whole tokens were replaced
            return _rebuild(raw, tokens, dict.fromkeys(range(len(tokens)), _REDACTED))
        hit = {
            i
            for i in _touched(current, changed(result, steps))
            if not _redacted(result[current[i][1] : current[i][2]])
        }
        if not hit:
            break
        result = _rebuild(result, current, dict.fromkeys(hit, _REDACTED))
    return result


def _escaped(
    raw: bytes,
    raw_tokens: list[Token],
    out: bytes,
    tokens: list[Token],
    scan: Scan,
    steps: list[Step],
    depth: int,
) -> bytes:
    picks: dict[int, bytes] = {}
    for index, (kind, start, end, _) in enumerate(tokens):
        original = raw[raw_tokens[index][1] : raw_tokens[index][2]]
        token = out[start:end]
        if kind != "s" or _redacted(token) or (token == original and b"\\" not in original):
            continue
        # From the scan's output, so nothing the scan removed comes back; checked
        # against the original's own full redaction (a rule that ran past a quote
        # or an escaped "\\n" cannot fool it). Clean unchanged text has nothing to
        # check (no step alone removes anything from it); a label hides no word.
        fine = _decoded(original, scan, steps, depth)
        if token == original or (fine is not None and within(_text(fine), _text(token))):
            if fine is None:
                continue  # clean at every depth: no step alone removes anything
            result = fine  # stands in for a second rescan (which doubles per level)
        else:
            result = _decoded(token, scan, steps, depth) or token
        if not _redacted(result) and _survives(original, result, steps, fine):
            result = _REDACTED
        if result != token:
            picks[index] = result
    return _rebuild(out, tokens, picks) if picks else out


def redact_json(raw: bytes, scan: Scan, steps: list[Step], depth: int = 0) -> bytes:
    """*raw* through *scan*; a JSON (or JSON Lines) document stays one."""
    # One leading byte-order mark is kept and skipped, never recursed on: a run of
    # U+FEFF is ordinary text (the tokenizer rejects it, so the scan's output stays).
    bom = _BOM if raw.startswith(_BOM) else b""
    return bom + _redacted_body(raw[len(bom) :], scan, steps, depth)


def _redacted_body(raw: bytes, scan: Scan, steps: list[Step], depth: int) -> bytes:
    out = scan(raw)
    if len(raw) > MAX_REPAIR_BYTES:
        return out
    raw_tokens = parse_blob(raw)
    if raw_tokens is None:
        return out
    tokens = raw_tokens
    if out != raw:
        scanned = parse_blob(out)
        if (
            scanned is None
            or shape(scanned) != shape(raw_tokens)
            or _collisions(out, scanned) > _collisions(raw, raw_tokens)
        ):
            return _splice(raw, raw_tokens, scan, steps, depth)
        tokens = scanned
    if out == raw and b"\\" not in raw:
        return out
    return _escaped(raw, raw_tokens, out, tokens, scan, steps, depth)


__all__ = ["MAX_REPAIR_BYTES", "redact_json"]
