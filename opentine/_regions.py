"""Editable regions in source files (0.87): the pure layout and comparison.

A file an optimizer may edit marks the code it may change between two marker
lines, each a whole-line comment::

    # EVOLVE-BLOCK-START
    def heuristic(x):
        return x * 2
    # EVOLVE-BLOCK-END

The comment leader may be ``#``, ``//``, ``--``, ``;``, ``/*`` or ``<!--`` (a
block comment may close on the same line). Everything else in the file is
locked: :func:`layout` splits the bytes into the locked *segments* (the text
before, between and after the regions, marker lines included) and digests each
one, so a later edit anywhere outside a region changes a segment digest, and
moving a marker moves a locked line into or out of a segment.

Marker tampering is reported, never guessed around (fail closed):

* a START inside an open region (nested), an END with no START, or a START
  with no END (unbalanced);
* a line that folds (NFKC, case-folded, letters only) to ``evolveblock`` but
  is not an exact marker line: a renamed, look-alike, trailing or CR-split
  marker;
* in a ``.py`` file, a marker line that the tokenizer does not see as a
  statement-level comment (inside a string or an open bracket, or an END right
  after a decorator line), or a file it cannot tokenize while it holds a marker.

The bytes are digested as they are: a CRLF or Unicode normalisation change
outside a region is an edit. A file that is not UTF-8 is one locked segment.
"""

from __future__ import annotations

import hashlib
import io
import re
import tokenize
import unicodedata
from typing import Any

START = "EVOLVE-BLOCK-START"
END = "EVOLVE-BLOCK-END"
_MARKER = re.compile(
    r"\A[ \t]*(?:#|//|--|;|/\*|<!--)[ \t]*EVOLVE-BLOCK-(START|END)"
    r"[ \t]*(?:\*/|-->)?[ \t]*\r?\n?\Z"
)
_LETTERS = re.compile(r"[^a-z]")
INVALID = "fail:region-marker-invalid"
OUTSIDE = "fail:region-outside-modified"
ADDED = "fail:region-file-added"
REMOVED = "fail:region-file-removed"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _lines(text: str) -> list[str]:
    """Lines split on ``\\n`` only, each keeping its end (unlike ``splitlines``)."""
    parts = text.split("\n")
    out = [p + "\n" for p in parts[:-1]]
    return out + ([parts[-1]] if parts[-1] else [])


def _lookalike(line: str) -> bool:
    folded = unicodedata.normalize("NFKC", line).casefold()
    return "evolveblock" in _LETTERS.sub("", folded)


def _comment_lines(text: str) -> dict[int, str] | None:
    """Whole-line Python comments by 1-based line, each with why it cannot hold a marker.

    ``""`` is a plain statement-level comment; ``"in a bracket"`` is inside an
    open bracket and ``"after a decorator"`` follows a decorator line, where a
    region would reach across the locked lines after it. ``None`` if the text cannot be tokenized.
    """
    found: dict[int, str] = {}
    depth, first, decorating, decorated = 0, True, False, False
    skip = (tokenize.NL, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT)
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text, newline="").readline):
            if tok.type == tokenize.COMMENT and not tok.line[: tok.start[1]].strip(" \t"):
                why = "after a decorator" if decorated else ""
                found[tok.start[0]] = "in a bracket" if depth else why
            if tok.type == tokenize.NEWLINE:
                first, decorated, decorating = True, decorating, False
            elif tok.type not in skip and tok.type != tokenize.ENDMARKER:
                if first:
                    first, decorated, decorating = False, False, tok.string == "@"
                if tok.type == tokenize.OP and tok.string in "([{":
                    depth += 1
                elif tok.type == tokenize.OP and tok.string in ")]}":
                    depth -= 1
    except (tokenize.TokenError, SyntaxError, IndentationError, ValueError):
        return None
    return found


def layout(path: str, data: bytes) -> dict[str, Any]:
    """``{sha256, regions, segments, errors}`` for one file's bytes."""
    whole = _sha(data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {"sha256": whole, "regions": 0, "segments": [whole], "errors": []}
    if text.startswith("﻿"):
        text = text[1:]
        prefix = "﻿"
    else:
        prefix = ""
    lines = _lines(text)
    if lines:
        lines[0] = prefix + lines[0]
    errors: list[str] = []
    comments = None
    if path.lower().endswith((".py", ".pyi", ".pyw")) and any(_lookalike(x) for x in lines):
        comments = _comment_lines(text)
        if comments is None:
            errors.append("the file holds a marker but cannot be tokenized")
    segments: list[str] = []
    current: list[str] = []
    open_at = 0
    for number, line in enumerate(lines, 1):
        bare = line[1:] if number == 1 and prefix else line
        match = _MARKER.match(bare)
        if match is None:
            if _lookalike(line):
                errors.append(f"line {number}: not an exact {START}/{END} comment line")
            if not open_at:
                current.append(line)
            continue
        why = comments.get(number, "inside a string") if comments is not None else ""
        if why == "after a decorator" and match.group(1) == "START":
            why = ""  # a locked decorator over a region's code is the owner's layout
        if why:
            errors.append(f"line {number}: the marker is not a statement-level comment ({why})")
        if match.group(1) == "START":
            if open_at:
                errors.append(f"line {number}: {START} inside the region opened on {open_at}")
                continue
            current.append(line)
            segments.append(_sha("".join(current).encode("utf-8")))
            current, open_at = [], number
        else:
            if not open_at:
                errors.append(f"line {number}: {END} with no open region")
                current.append(line)
                continue
            current, open_at = [line], 0
    if open_at:
        errors.append(f"line {open_at}: {START} is never closed")
    segments.append(_sha("".join(current).encode("utf-8")))
    return {"sha256": whole, "regions": len(segments) - 1, "segments": segments,
            "errors": errors}  # fmt: skip


def finding(code: str, path: str, detail: str) -> dict[str, str]:
    return {"level": "fail", "code": code, "surface": "regions", "path": path, "detail": detail}


def compare(pinned: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]) -> list:
    """Findings for *current* file layouts against the *pinned* ones, sorted by path."""
    out = []
    for path in sorted(set(pinned) | set(current)):
        was, now = pinned.get(path), current.get(path)
        if was is None:
            out.append(finding(ADDED, path, "a file the pin does not list"))
            continue
        if now is None:
            out.append(finding(REMOVED, path, "a pinned file is gone"))
            continue
        if now["errors"]:
            out += [finding(INVALID, path, why) for why in now["errors"]]
            continue
        if now["regions"] != was["regions"]:
            why = f"{now['regions']} regions where {was['regions']} were pinned"
            out.append(finding(INVALID, path, why))
            continue
        for index, (a, b) in enumerate(zip(was["segments"], now["segments"], strict=True)):
            if a != b:
                out.append(finding(OUTSIDE, path, f"locked segment {index} changed"))
    return out


__all__ = ["ADDED", "END", "INVALID", "OUTSIDE", "REMOVED", "START", "compare", "finding",
           "layout"]  # fmt: skip
