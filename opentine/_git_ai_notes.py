"""Git AI Standard v3 authorship notes (``authorship/3.0.0``): reader and writer.

Git AI (github.com/git-ai-project/git-ai) keeps one note per commit under
``refs/notes/ai``. The note is an attestation section, a line holding only
``---``, then a JSON metadata object::

    src/app.py
      s_0123456789abcd::t_0123456789abcd 1-3,7
      h_0123456789abcd 4
    ---
    {"schema_version": "authorship/3.0.0", "base_commit_sha": "...", "prompts": {},
     "sessions": {"s_0123456789abcd": {"agent_id": {"tool": "...", "id": "...",
     "model": "..."}}}, "humans": {"h_0123456789abcd": {"author": "Ada <ada@x>"}}}

File paths start at column 0 (JSON-quoted when they hold a space, tab, quote
or newline); each attestation is two spaces, a key, a space and 1-indexed
ranges (``N``, ``N-M``, comma separated). Keys are ``s_<14hex>::t_<14hex>``
(a session and one of its checkpoints), ``h_<14hex>`` (a human) or a legacy
16-hex (or 7-hex) prompt hash.

OpenTine's own notes stay canonical; converting to and from them is
:mod:`opentine._git_ai_convert`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from opentine._git_link import IDENTITY_ENV, GitLinkError, git

REF = "refs/notes/ai"
VERSION = "authorship/3.0.0"
RUN_PREFIX = "git-ai:"
SESSION_KEY = re.compile(r"^(s_[0-9a-f]{14})::(t_[0-9a-f]{14})$")
HUMAN_KEY = re.compile(r"^h_[0-9a-f]{14}$")
PROMPT_KEY = re.compile(r"^(?:[0-9a-f]{16}|[0-9a-f]{7})$")
_RANGES = re.compile(r"^[1-9][0-9]*(?:-[1-9][0-9]*)?(?:,[1-9][0-9]*(?:-[1-9][0-9]*)?)*$")
MAX_LINES = 200_000


class GitAiFormatError(ValueError):
    """A note that is not a well-formed Git AI v3 authorship log."""


def parse_ranges(text: str) -> list[int]:
    if not _RANGES.match(text):
        raise GitAiFormatError(f"bad line ranges: {text[:40]!r}")
    lines: list[int] = []
    for part in text.split(","):
        low, _, high = part.partition("-")
        start, end = int(low), int(high or low)
        if end < start or len(lines) + end - start >= MAX_LINES:
            raise GitAiFormatError(f"bad line range: {part[:40]!r}")
        lines.extend(range(start, end + 1))
    return sorted(set(lines))


def spans(lines: list[int]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for number in sorted(set(lines)):
        if out and number == out[-1][1] + 1:
            out[-1] = (out[-1][0], number)
        else:
            out.append((number, number))
    return out


def format_ranges(lines: list[int]) -> str:
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in spans(lines))


def parse(text: str) -> dict[str, Any]:
    """``{"files": {path: {key: [line, ...]}}, "metadata": {...}}`` of a v3 note."""
    text = text.replace("\r\n", "\n")
    head, sep, tail = text.partition("\n---\n")
    if not sep:
        if not text.startswith("---\n"):
            raise GitAiFormatError("no '---' divider")
        head, tail = "", text[4:]
    try:
        metadata = json.loads(tail)
    except ValueError as exc:
        raise GitAiFormatError(f"metadata is not JSON: {exc}") from exc
    if not isinstance(metadata, dict) or metadata.get("schema_version") != VERSION:
        raise GitAiFormatError(f"not {VERSION}")
    if not isinstance(metadata.get("prompts"), dict):
        raise GitAiFormatError("metadata has no prompts map")
    files: dict[str, dict[str, list[int]]] = {}
    path: str | None = None
    for raw in head.split("\n"):
        if not raw.strip():
            continue
        if not raw.startswith(" "):
            try:
                path = json.loads(raw) if raw.startswith('"') else raw
            except ValueError as exc:
                raise GitAiFormatError("bad quoted file path") from exc
            if not safe_path(path):
                raise GitAiFormatError(f"bad file path: {str(path)[:40]!r}")
            files.setdefault(path, {})
            continue
        if path is None or not raw.startswith("  "):
            raise GitAiFormatError("attestation before any file path")
        key, _, ranges = raw[2:].partition(" ")
        if not valid_key(key):
            raise GitAiFormatError(f"bad attestation key: {key[:40]!r}")
        files[path][key] = sorted(set(files[path].get(key, [])) | set(parse_ranges(ranges)))
    return {"files": files, "metadata": metadata}


def safe_path(path: object) -> bool:
    """A repository-relative POSIX path: no root, drive, ``..``, backslash or control."""
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        return False
    if any(ord(c) < 32 or c == "\x7f" for c in path) or re.match(r"^[A-Za-z]:", path):
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def valid_key(key: str) -> bool:
    return bool(SESSION_KEY.match(key) or HUMAN_KEY.match(key) or PROMPT_KEY.match(key))


def _quote(path: str) -> str:
    return json.dumps(path) if any(c in path for c in ' \t\n"') else path


def render(files: dict[str, dict[str, list[int]]], metadata: dict[str, Any]) -> str:
    lines = []
    for path in sorted(files):
        if not any(files[path].values()):
            continue
        if not safe_path(path):
            raise GitAiFormatError(f"bad file path: {path[:40]!r}")
        bad = [key for key in files[path] if not valid_key(key)]
        if bad:
            raise GitAiFormatError(f"bad attestation key: {bad[0][:40]!r}")
        lines.append(_quote(path))
        for key in sorted(files[path]):
            if files[path][key]:
                lines.append(f"  {key} {format_ranges(files[path][key])}")
    body = json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False)
    return "\n".join([*lines, "---", body]) + "\n"


def read(cwd: Path | str, sha: str) -> dict[str, Any] | None:
    try:
        text = git(cwd, "notes", f"--ref={REF}", "show", sha)
    except GitLinkError:
        return None
    return parse(text)


def noted_commits(cwd: Path | str) -> list[str]:
    try:
        listed = git(cwd, "notes", f"--ref={REF}", "list")
    except GitLinkError:
        return []
    return [row.split()[1] for row in listed.splitlines() if len(row.split()) == 2]


def write(cwd: Path | str, sha: str, text: str) -> None:
    git(
        cwd,
        "notes",
        f"--ref={REF}",
        "add",
        "-f",
        "-F",
        "-",
        sha,
        stdin=text.encode("utf-8"),
        keep_env=IDENTITY_ENV,
    )


__all__ = [
    "REF",
    "VERSION",
    "GitAiFormatError",
    "noted_commits",
    "parse",
    "read",
    "render",
    "write",
]
