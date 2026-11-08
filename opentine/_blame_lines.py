"""``tine blame FILE --porcelain | --lines``: git blame with agent lines marked (0.45).

The output is ``git blame --porcelain`` as git wrote it, byte for byte, with
three header lines added before each content line a line attribution note
(:mod:`opentine._line_attrib`) credits to an agent::

    tine-run <run>
    tine-step <seq>
    tine-model <model>

A file with no attributed lines therefore blames exactly as git does. The
porcelain format allows extra header lines (readers key on the first word),
so git-blame tooling keeps working. ``--json`` emits ``tine-blame/1``.

Blame reads the committed revision (``HEAD`` unless ``--rev``) with textconv
off: blaming the work tree runs the repository's own filter programs.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from opentine._git_link import GitLinkError, checked_revision, git_raw
from opentine._line_attrib import read_note

SCHEMA = "tine-blame/1"
_HEADER = re.compile(rb"^([0-9a-f]{40,64}) (\d+) (\d+)(?: \d+)?$")
_RANGE = re.compile(r"^\d{1,9},\d{1,9}$")
_ZERO = re.compile(r"^0+$")
#: A note is repository data anyone can push: cap how many lines it may credit.
MAX_NOTE_LINES = 200_000
_UNSAFE = re.compile(r"[\x00-\x20\x7f]")


def _word(value: Any) -> str:
    """*value* as one header word: no whitespace or control bytes (no forged headers)."""
    return _UNSAFE.sub("_", str(value or ""))[:200]


def _note_lines(cwd: Path | str, sha: str) -> dict[str, dict[int, dict[str, Any]]]:
    """``{path: {line: {run, seq, model}}}`` from *sha*'s attribution note."""
    out: dict[str, dict[int, dict[str, Any]]] = {}
    if _ZERO.fullmatch(sha):
        return out
    try:
        record = read_note(cwd, sha)
    except (GitLinkError, ValueError):
        return out
    budget = MAX_NOTE_LINES
    files = (record or {}).get("files")
    for entry in files if isinstance(files, list) else []:
        ranges = entry.get("ranges") if isinstance(entry, dict) else None
        if not isinstance(ranges, list):
            continue
        lines = out.setdefault(str(entry.get("path")), {})
        for item in ranges:
            start = item.get("start_line") if isinstance(item, dict) else None
            end = item.get("end_line") if isinstance(item, dict) else None
            if not (type(start) is int and type(end) is int and 1 <= start <= end):
                continue  # a malformed range credits nothing
            seq = item.get("seq")
            found = {
                "run": _word(item.get("run")),
                "seq": seq if type(seq) is int else None,
                "model": _word(item.get("model")),
            }
            end = min(end, start + budget - 1)
            budget -= end - start + 1
            for number in range(start, end + 1):
                lines[number] = found
            if budget <= 0:
                return out
    return out


def raw_blame(
    cwd: Path | str, path: str, *, rev: str = "HEAD", lines: str = "", line_porcelain=False
) -> bytes:
    """``git blame --porcelain`` (or ``--line-porcelain``) bytes for *path* at *rev*."""
    if lines and not _RANGE.fullmatch(lines):
        raise ValueError("-L takes START,END line numbers")
    args = ["blame", "--line-porcelain" if line_porcelain else "--porcelain", "--no-textconv"]
    if lines:
        args += ["-L", lines]
    return git_raw(cwd, *args, checked_revision(rev), "--", path)


def _walk(raw: bytes):
    """Yield ``(line bytes, (sha, orig line, orig path) or None)`` for each porcelain line."""
    # git prints ``filename`` only the first time it names a commit (unless the
    # commit touches several paths), so remember the path per commit.
    sha, orig, names = "", 0, {}
    for line in raw.splitlines(keepends=True):
        body = line.rstrip(b"\n")
        if body.startswith(b"\t"):
            yield line, (sha, orig, names.get(sha, ""))
            continue
        if match := _HEADER.match(body):
            sha, orig = match.group(1).decode(), int(match.group(2))
        elif body.startswith(b"filename "):
            names[sha] = body[len(b"filename ") :].decode("utf-8", "replace")
        yield line, None


class _Notes:
    def __init__(self, cwd: Path | str) -> None:
        self.cwd, self.cache = cwd, {}

    def find(self, key: tuple[str, int, str]) -> dict[str, Any] | None:
        sha, orig, name = key
        if sha not in self.cache:
            self.cache[sha] = _note_lines(self.cwd, sha)
        return self.cache[sha].get(name, {}).get(orig)


def annotate(cwd: Path | str, raw: bytes) -> bytes:
    """*raw* porcelain with ``tine-*`` headers before every agent-attributed line."""
    notes, out = _Notes(cwd), bytearray()
    for line, key in _walk(raw):
        found = notes.find(key) if key else None
        if found:
            seq = "" if found["seq"] is None else str(found["seq"])
            for word, value in (("run", found["run"]), ("step", seq), ("model", found["model"])):
                out += f"tine-{word} {value}\n".encode()
        out += line
    return bytes(out)


def _row(fields: dict[bytes, bytes]) -> dict[str, Any]:
    text = {key.decode(): value.decode("utf-8", "replace") for key, value in fields.items()}
    return {
        "author": text.get("author", ""),
        "author_mail": text.get("author-mail", ""),
        "author_time": int(text.get("author-time") or 0),
        "summary": text.get("summary", ""),
    }


def blame_record(cwd: Path | str, path: str, *, rev: str = "HEAD", lines: str = "") -> dict:
    """The ``tine-blame/1`` record for *path* at *rev*."""
    raw = raw_blame(cwd, path, rev=rev, lines=lines, line_porcelain=True)
    notes, rows, fields = _Notes(cwd), [], {}
    final = 0
    for line, key in _walk(raw):
        body = line.rstrip(b"\n")
        if key is None:
            if match := _HEADER.match(body):
                final, fields = int(match.group(3)), {}
            else:
                word, _, value = body.partition(b" ")
                fields[word] = value
            continue
        sha, orig, name = key
        found = notes.find(key)
        rows.append({
            "line": final,
            "commit": "" if _ZERO.fullmatch(sha) else sha,
            "orig_path": name,
            "orig_line": orig,
            **_row(fields),
            "text": body[1:].decode("utf-8", "replace"),
            "ai": dict(found) if found else None,
        })  # fmt: skip
    ai = sum(1 for row in rows if row["ai"])
    return {
        "command": "blame",
        "schema": SCHEMA,
        "path": path,
        "revision": rev,
        "lines": rows,
        "total_lines": len(rows),
        "ai_lines": ai,
    }


__all__ = ["SCHEMA", "annotate", "blame_record", "raw_blame"]
