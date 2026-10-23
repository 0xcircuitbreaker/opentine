"""``.tineignore``: paths a run's code capture must leave out or redact.

A run records the working tree it started from -- the git patch, the staged
patch and the list of untracked files (``trace.capture.code_manifest``). Some
of that should never enter a run: generated bundles, local datasets, a
``secrets/`` directory that git ignores locally but a patch can still show. A
``.tineignore`` at the worktree root lists them, one glob per line::

    # comments and blank lines are ignored
    dist/**             leave the path out of the capture entirely
    redact:config/*.env keep the path, replace its patch hunks with a marker

Globs use ``fnmatch`` against the repository-relative POSIX path; a pattern
ending in ``/`` or ``/**`` matches everything under that directory. The file is
bounded (64 KiB, 1,000 patterns) and read as UTF-8; a malformed file is an error
rather than a silent no-op, so a typo cannot quietly capture what it meant to
hide.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

FILE_NAME = ".tineignore"
MAX_BYTES = 64 * 1024
MAX_PATTERNS = 1000
REDACTED = "[tineignore: redacted]"
_DIFF_PREFIX = "diff --git "
_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


@dataclass(frozen=True)
class IgnoreRules:
    exclude: tuple[str, ...] = ()
    redact: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.exclude or self.redact)

    def excluded(self, path: str) -> bool:
        return _any(path, self.exclude)

    def redacted(self, path: str) -> bool:
        return _any(path, self.redact)


def _normalize(pattern: str) -> str:
    pattern = pattern.strip().lstrip("/")
    if pattern.endswith("/"):
        pattern += "**"
    return pattern


def _any(path: str, patterns: tuple[str, ...]) -> bool:
    path = path.lstrip("/")
    for pattern in patterns:
        if fnmatch.fnmatchcase(path, pattern):
            return True
        if pattern.endswith("/**") and (path + "/").startswith(pattern[:-2]):
            return True
    return False


def parse(text: str) -> IgnoreRules:
    exclude: list[str] = []
    redact: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        target = redact if line.startswith("redact:") else exclude
        pattern = _normalize(line.removeprefix("redact:"))
        if not pattern:
            raise ValueError(f"{FILE_NAME}: empty pattern in {line!r}")
        target.append(pattern)
    if len(exclude) + len(redact) > MAX_PATTERNS:
        raise ValueError(f"{FILE_NAME} has more than {MAX_PATTERNS} patterns")
    return IgnoreRules(tuple(exclude), tuple(redact))


def load(root: str | Path) -> IgnoreRules:
    """The rules at ``root/.tineignore``; empty rules when there is no file."""
    path = Path(root) / FILE_NAME
    if path.is_symlink():
        raise ValueError(f"{FILE_NAME} must be a regular file, not a link")
    try:
        raw = path.read_bytes()[: MAX_BYTES + 1]
    except FileNotFoundError:
        return IgnoreRules()
    if len(raw) > MAX_BYTES:
        raise ValueError(f"{FILE_NAME} exceeds {MAX_BYTES} bytes")
    return parse(raw.decode("utf-8"))


def _unquote(text: str, start: int) -> tuple[str, int] | None:
    """A C-quoted git path starting at ``text[start] == '"'``, and the index after it."""
    raw = bytearray()
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == '"':
            return raw.decode("utf-8", errors="replace"), index + 1
        if char != "\\":
            raw += char.encode("utf-8")
            index += 1
            continue
        escape = text[index + 1 : index + 2]
        if escape in _ESCAPES:
            raw.append(_ESCAPES[escape])
            index += 2
        elif len(text) >= index + 4 and all(c in "01234567" for c in text[index + 1 : index + 4]):
            raw.append(int(text[index + 1 : index + 4], 8) & 0xFF)
            index += 4
        else:
            return None
    return None


def header_paths(line: str) -> tuple[str, ...] | None:
    """The a/ and b/ paths of a ``diff --git`` header, or None when ambiguous.

    git C-quotes a path with quotes, backslashes or control characters (and,
    unless ``core.quotePath=false``, non-ASCII bytes). An unquoted header is
    split where both halves name the same file; a rename between two unquoted
    names containing ``" b/"`` cannot be split unambiguously and returns None.
    """
    body = line[len(_DIFF_PREFIX) :]
    paths: list[str] = []
    index = 0
    while index < len(body) and len(paths) < 2:
        if body[index] == '"':
            parsed = _unquote(body, index)
            if parsed is None:
                return None
            paths.append(parsed[0])
            index = parsed[1] + 1
            continue
        if len(paths) == 0 and '"' not in body:
            size = len(body) - 5
            if size > 0 and size % 2 == 0:
                half = size // 2
                first, second = body[: half + 2], body[half + 3 :]
                if body[half + 2] == " " and first[2:] == second[2:]:
                    paths = [first, second]
                    break
            if body.count(" b/") != 1:
                return None  # a rename whose names hide " b/": ambiguous
            split = body.index(" b/")
            paths = [body[:split], body[split + 1 :]]
            break
        end = body.find(" ", index) if len(paths) == 0 else len(body)
        if end < 0:
            return None
        paths.append(body[index:end])
        index = end + 1
    if len(paths) != 2 or not all(len(p) > 2 and p[1] == "/" for p in paths):
        return None
    return tuple(path[2:] for path in paths)


def filter_patch(patch: str, rules: IgnoreRules) -> str:
    """*patch* without excluded files' sections, and with redacted files' hunks masked.

    A section whose header cannot be parsed is dropped while rules are active:
    an unreadable path must not be captured when it might be one to hide.
    """
    if not rules or not patch:
        return patch
    out: list[str] = []
    mode = "keep"
    for line in patch.splitlines(keepends=True):
        text = line.rstrip("\r\n")
        if text.startswith(_DIFF_PREFIX):
            paths = header_paths(text)
            if paths is None or any(rules.excluded(path) for path in paths):
                mode = "drop"
            elif any(rules.redacted(path) for path in paths):
                mode = "redact"
            else:
                mode = "keep"
            if mode != "drop":
                out.append(line)
            if mode == "redact":
                out.append(REDACTED + "\n")
            continue
        if mode == "keep":
            out.append(line)
    return "".join(out)


def filter_paths(paths: list[str], rules: IgnoreRules) -> list[str]:
    return [path for path in paths if not rules.excluded(path)]


__all__ = ["FILE_NAME", "IgnoreRules", "filter_patch", "filter_paths", "load", "parse"]
