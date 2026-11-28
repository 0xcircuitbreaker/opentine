"""Text helpers of the structural diff (0.88): hidden-edit flags, tokens, prompt sections.

A file is unchanged only when its bytes are. Every other helper here explains
*how* two byte strings differ, so an edit built to look like no change (an
invisible character, a bidirectional control, a look-alike letter, a line-ending
or whitespace-only rewrite) is still listed and named:

``invisible``     a zero-width or other format character (category ``Cf``) was added;
``bidi``          a bidirectional control was added (it can reorder what a reader sees);
``non-ascii``     a non-ASCII letter was added (a look-alike of an ASCII one, perhaps);
``nfkc``          the two texts are equal after NFKC normalisation (Python identifiers
                  are compared after NFKC, so the AST cannot tell them apart);
``line-endings``  the number of CRLF line endings changed;
``whitespace``    the two texts are equal once whitespace is ignored.
"""

from __future__ import annotations

import difflib
import hashlib
import re
import unicodedata
from typing import Any

BIDI = frozenset("؜‎‏‪‫‬‭‮⁦⁧⁨⁩")
TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)
HEADING_RE = re.compile(r"(?m)^ {0,3}(#{1,6})[ \t]+(.*?)[ \t#]*$")
MAX_TOKENS = 200_000  # per side; past it the token diff reports counts only
MAX_HUNKS = 20


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def decode(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _counts(text: str) -> dict[str, int]:
    out = {"invisible": 0, "bidi": 0, "non-ascii": 0, "crlf": text.count("\r\n")}
    for ch in text:
        if ch in BIDI:
            out["bidi"] += 1
        elif unicodedata.category(ch) == "Cf":
            out["invisible"] += 1
        elif ord(ch) > 127 and ch.isalpha():
            out["non-ascii"] += 1
    return out


def flags(before: str, after: str) -> list[str]:
    """The hidden-edit flags of *after* against *before* (sorted, maybe empty)."""
    old, new = _counts(before), _counts(after)
    out = {name for name in ("invisible", "bidi", "non-ascii") if new[name] > old[name]}
    if old["crlf"] != new["crlf"]:
        out.add("line-endings")
    if before != after and unicodedata.normalize("NFKC", before) == unicodedata.normalize(
        "NFKC", after
    ):
        out.add("nfkc")
    if before != after and "".join(before.split()) == "".join(after.split()):
        out.add("whitespace")
    return sorted(out)


def shown(text: str, limit: int = 80) -> str:
    """*text* with every non-printable or non-ASCII character escaped, so it reads as is."""
    out = "".join(ch if 32 <= ord(ch) < 127 else f"\\u{ord(ch):04x}" for ch in text)
    return out if len(out) <= limit else out[: limit - 3] + "..."


def token_diff(before: str, after: str) -> dict[str, Any]:
    """Whitespace-insensitive token diff: ``{"structural", "inserted", "deleted", "hunks"}``."""
    old, new = TOKEN_RE.findall(before), TOKEN_RE.findall(after)
    if old == new:
        return {"structural": False, "inserted": 0, "deleted": 0, "hunks": []}
    if len(old) > MAX_TOKENS or len(new) > MAX_TOKENS:
        return {"structural": True, "inserted": len(new), "deleted": len(old), "hunks": [],
                "truncated": True}  # fmt: skip
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    inserted = deleted = 0
    hunks = []
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == "equal":
            continue
        deleted, inserted = deleted + (i2 - i1), inserted + (j2 - j1)
        if len(hunks) < MAX_HUNKS:
            hunks.append({"op": op, "at": i1, "before": shown(" ".join(old[i1:i2])),
                          "after": shown(" ".join(new[j1:j2]))})  # fmt: skip
    return {"structural": True, "inserted": inserted, "deleted": deleted, "hunks": hunks}


def sections(text: str) -> list[tuple[str, str]]:
    """``[(key, body)]``: the preamble, then one entry per ATX heading.

    A key is the heading path (``Parent / Child``) with ``#N`` appended to a
    repeated one, so two sections with one title stay two sections.
    """
    out: list[tuple[str, str]] = []
    stack: list[tuple[int, str]] = []
    seen: dict[str, int] = {}
    cursor, key = 0, "(preamble)"
    for match in HEADING_RE.finditer(text):
        out.append((key, text[cursor : match.start()]))
        level, title = len(match.group(1)), match.group(2)
        stack = [(lvl, name) for lvl, name in stack if lvl < level] + [(level, title)]
        key = " / ".join(name for _, name in stack)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            key = f"{key} #{seen[key]}"
        cursor = match.start()
    out.append((key, text[cursor:]))
    return [(k, body) for k, body in out if k != "(preamble)" or body]


def section_diff(before: str, after: str) -> list[dict[str, Any]]:
    """Added, removed and changed sections, each with the hidden-edit flags of its body."""
    old, new = dict(sections(before)), dict(sections(after))
    changes = []
    for key in sorted(set(old) | set(new)):
        if key not in new:
            changes.append({"op": "removed", "item": shown(key, 200)})
        elif key not in old:
            changes.append({"op": "added", "item": shown(key, 200)})
        elif old[key] != new[key]:
            changes.append({"op": "changed", "item": shown(key, 200),
                            "flags": flags(old[key], new[key])})  # fmt: skip
    old_order = [k for k, _ in sections(before) if k in new]
    new_order = [k for k, _ in sections(after) if k in old]
    if old_order != new_order:
        changes.append({"op": "reordered", "item": "sections"})
    return changes


__all__ = ["decode", "flags", "section_diff", "sections", "sha", "shown", "token_diff"]
