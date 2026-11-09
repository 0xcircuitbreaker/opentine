"""Check that bytes are the git object an id names (0.46.1, SPEC 4.18).

A git object id is the hash of ``<type> SP <decimal length> NUL <bytes>``:
SHA-1 for a ``sha1`` repository (40 hex), SHA-256 for a ``sha256`` one (64
hex). :func:`check` recomputes it for a ``blob``, ``tree``, ``commit`` or
``tag`` and returns the ids the object links (a tree's entries in order, a
commit's tree then parents, a tag's object), so a caller can walk a mirrored
history and check every link it holds. A match means only that the bytes are
the object the id names (``matches its id (checked by you)``); it says nothing
about whether an upstream holds that id. SHA-1 is plain SHA-1 here; SHA-1DC
collision detection is not implemented (SPEC 4.18). Reference for the
``git-object.check`` conformance op, ported to the pyz and the TS verifier.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

TYPES = ("blob", "tree", "commit", "tag")
FORMATS = {40: "sha1", 64: "sha256"}
LABEL = "matches its id (checked by you)"
MAX_OBJECT_BYTES = 64 * 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_MODE = re.compile(rb"[0-7]{5,6}")


class GitObjectError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _malformed(message: str) -> GitObjectError:
    return GitObjectError("git-object.malformed", f"git object is malformed: {message}")


def object_id(kind: str, data: bytes, object_format: str = "sha1") -> str:
    if kind not in TYPES:
        raise _malformed(f"type is one of {', '.join(TYPES)}")
    if object_format not in ("sha1", "sha256"):
        raise _malformed("object_format is sha1 or sha256")
    framed = kind.encode("ascii") + b" " + str(len(data)).encode("ascii") + b"\0" + data
    return hashlib.new(object_format, framed).hexdigest()


def _tree(data: bytes, width: int) -> list[str]:
    links, at = [], 0
    while at < len(data):
        space = data.find(b" ", at)
        nul = data.find(b"\0", space + 1) if space >= 0 else -1
        if space < 0 or nul < 0 or not _MODE.fullmatch(data[at:space]) or nul == space + 1:
            raise _malformed("a tree entry is <mode> SP <name> NUL <id>")
        if b"/" in data[space + 1 : nul] or data[space + 1 : nul] in (b".", b".."):
            raise _malformed("a tree entry name is one path component")
        raw = data[nul + 1 : nul + 1 + width]
        if len(raw) != width:
            raise _malformed("a tree entry id is truncated")
        links.append(raw.hex())
        at = nul + 1 + width
    return links


def _headers(data: bytes) -> list[tuple[str, str]]:
    head = data.split(b"\n\n", 1)[0]
    try:
        lines = head.decode("utf-8").split("\n")
    except UnicodeDecodeError as exc:
        raise _malformed("headers are UTF-8") from exc
    return [tuple(line.split(" ", 1)) for line in lines if " " in line]  # type: ignore[misc]


def links(kind: str, data: bytes, object_format: str) -> list[str]:
    """The ids *data* (an object of *kind*) links, in order."""
    width = 20 if object_format == "sha1" else 32
    if kind == "blob":
        return []
    if kind == "tree":
        return _tree(data, width)
    headers = _headers(data)
    first = "tree" if kind == "commit" else "object"
    if not headers or headers[0][0] != first:
        raise _malformed(f"a {kind} starts with a {first} header")
    found = [headers[0][1]]
    if kind == "commit":
        found += [value for name, value in headers[1:] if name == "parent"]
    if not all(len(oid) == width * 2 and _HEX.fullmatch(oid) for oid in found):
        raise _malformed(f"a {kind} links {object_format} ids")
    return found


def check(kind: Any, data: bytes, oid: Any) -> dict[str, Any]:
    """``{oid, type, object_format, links, state, label}`` when *data* is *oid*; refuse else."""
    if not isinstance(oid, str) or not _HEX.fullmatch(oid):
        raise _malformed("the id is 40 or 64 lowercase hex")
    if kind not in TYPES:
        raise _malformed(f"type is one of {', '.join(TYPES)}")
    if len(data) > MAX_OBJECT_BYTES:
        raise _malformed("the object exceeds 64 MiB")
    object_format = FORMATS[len(oid)]
    if object_id(kind, data, object_format) != oid:
        raise GitObjectError("git-object.mismatch", f"the bytes do not hash to {kind} {oid}")
    return {
        "oid": oid,
        "type": kind,
        "object_format": object_format,
        "links": links(kind, data, object_format),
        "state": "matches",
        "label": LABEL,
    }


__all__ = ["FORMATS", "LABEL", "TYPES", "GitObjectError", "check", "links", "object_id"]
