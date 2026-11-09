"""The git object check (SPEC 4.18) with the standard library, for ``tine-verify.pyz``.

An independent port of ``opentine._git_object.check``: hash ``<type> SP <len>
NUL <bytes>`` with SHA-1 (40-hex ids) or SHA-256 (64-hex ids) and list the ids
a tree, commit or tag links. Plain SHA-1, as in the reference.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

TYPES = ("blob", "tree", "commit", "tag")
LABEL = "matches its id (checked by you)"
_HEX = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_MODE = re.compile(rb"[0-7]{5,6}")


class Refused(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _bad(message: str) -> Refused:
    return Refused("git-object.malformed", f"git object is malformed: {message}")


def _tree(data: bytes, width: int) -> list[str]:
    out, at = [], 0
    while at < len(data):
        space = data.find(b" ", at)
        nul = data.find(b"\0", space + 1) if space >= 0 else -1
        if space < 0 or nul < 0 or not _MODE.fullmatch(data[at:space]) or nul == space + 1:
            raise _bad("a tree entry is <mode> SP <name> NUL <id>")
        name = data[space + 1 : nul]
        if b"/" in name or name in (b".", b".."):
            raise _bad("a tree entry name is one path component")
        raw = data[nul + 1 : nul + 1 + width]
        if len(raw) != width:
            raise _bad("a tree entry id is truncated")
        out.append(raw.hex())
        at = nul + 1 + width
    return out


def _links(kind: str, data: bytes, width: int, fmt: str) -> list[str]:
    if kind == "blob":
        return []
    if kind == "tree":
        return _tree(data, width)
    try:
        lines = data.split(b"\n\n", 1)[0].decode("utf-8").split("\n")
    except UnicodeDecodeError as exc:
        raise _bad("headers are UTF-8") from exc
    headers = [line.split(" ", 1) for line in lines if " " in line]
    first = "tree" if kind == "commit" else "object"
    if not headers or headers[0][0] != first:
        raise _bad(f"a {kind} starts with a {first} header")
    found = [headers[0][1]]
    if kind == "commit":
        found += [value for name, value in headers[1:] if name == "parent"]
    if not all(len(oid) == width * 2 and _HEX.fullmatch(oid) for oid in found):
        raise _bad(f"a {kind} links {fmt} ids")
    return found


def check(kind: Any, data: bytes, oid: Any) -> dict[str, Any]:
    if not isinstance(oid, str) or not _HEX.fullmatch(oid):
        raise _bad("the id is 40 or 64 lowercase hex")
    if kind not in TYPES:
        raise _bad(f"type is one of {', '.join(TYPES)}")
    if len(data) > 64 * 1024 * 1024:
        raise _bad("the object exceeds 64 MiB")
    fmt = "sha1" if len(oid) == 40 else "sha256"
    framed = kind.encode("ascii") + b" " + str(len(data)).encode("ascii") + b"\0" + data
    if hashlib.new(fmt, framed).hexdigest() != oid:
        raise Refused("git-object.mismatch", f"the bytes do not hash to {kind} {oid}")
    width = 20 if fmt == "sha1" else 32
    return {
        "oid": oid,
        "type": kind,
        "object_format": fmt,
        "links": _links(kind, data, width, fmt),
        "state": "matches",
        "label": LABEL,
    }


__all__ = ["LABEL", "Refused", "check"]
