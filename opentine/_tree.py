"""Tree blobs: a content-addressed workspace directory (SPEC "Tree blobs").

A tree is a ``blob`` stored at schema 2 (:data:`opentine.kernel.TREE_SCHEMA`)
whose raw body is the RFC 8785 canonical JSON of::

    {"entries": [{"mode": "100644", "name": "a.txt", "oid": "blob:sha256:..."}, ...],
     "omitted": [{"name": "big.bin", "reason": "size"}],      # optional
     "type": "opentine.tree"}

Entries are sorted by the UTF-8 bytes of ``name`` and unique; a name is one
path component (no ``/``, ``\\``, NUL, ``.`` or ``..``). ``mode`` is ``100644``
(file), ``100755`` (executable file), ``120000`` (symbolic link: the blob holds
the link target, which is never followed) or ``40000`` (a subtree, itself a
tree blob). ``redacted: true`` marks a file whose stored bytes were scrubbed by
redaction, so it cannot be restored byte for byte. ``omitted`` names entries
deliberately left out (size limits, unreadable): a restore leaves those alone.

Encoding a tree as a blob, not a new object kind, keeps the 0.34 readers
working: 0.34 rejects unknown kinds, but accepts a blob at any schema, and its
prune walk finds the entry oids in the raw bytes.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from opentine.kernel import TREE_SCHEMA, KernelError, _parse_int, canonical_json, parse_oid

TREE_TYPE = "opentine.tree"
FILE, EXEC, LINK, DIR = "100644", "100755", "120000", "40000"
MODES = frozenset({FILE, EXEC, LINK, DIR})
MAX_ENTRIES = 100_000
MAX_DEPTH = 256


def _check_name(name: Any) -> str:
    if not isinstance(name, str) or not name or name in {".", ".."}:
        raise KernelError(f"invalid tree entry name: {name!r}")
    if any(ch in name for ch in "/\\\0"):
        raise KernelError(f"invalid tree entry name: {name!r}")
    name.encode("utf-8")
    return name


def encode_tree(entries: list[dict[str, Any]], omitted: list[dict[str, str]] = ()) -> bytes:
    """Canonical body for *entries* (sorted here) and *omitted* names."""
    rows = sorted(entries, key=lambda row: row["name"].encode("utf-8"))
    payload: dict[str, Any] = {"entries": rows, "type": TREE_TYPE}
    if omitted:
        payload["omitted"] = sorted(omitted, key=lambda row: row["name"].encode("utf-8"))
    body = canonical_json(payload)
    parse_tree(body)
    return body


def parse_tree(body: bytes) -> dict[str, Any]:
    """Validate a tree body; returns ``{"entries": [...], "omitted": [...]}``."""
    try:
        payload = json.loads(body, parse_int=_parse_int)
    except (ValueError, RecursionError) as exc:
        raise KernelError("malformed tree blob") from exc
    if not isinstance(payload, dict) or payload.get("type") != TREE_TYPE:
        raise KernelError("tree blob must declare type opentine.tree")
    if canonical_json(payload) != body:
        raise KernelError("non-canonical tree blob")
    if set(payload) - {"entries", "omitted", "type"}:
        raise KernelError("unknown tree fields")
    entries, omitted = payload.get("entries"), payload.get("omitted", [])
    if not isinstance(entries, list) or not isinstance(omitted, list):
        raise KernelError("tree entries and omitted must be lists")
    if len(entries) + len(omitted) > MAX_ENTRIES:
        raise KernelError("tree exceeds its entry limit")
    names: list[bytes] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - {"mode", "name", "oid", "redacted"}:
            raise KernelError("malformed tree entry")
        if entry.get("mode") not in MODES or entry.get("redacted", True) is not True:
            raise KernelError("invalid tree entry mode")
        if parse_oid(entry.get("oid"))[0] != "blob":
            raise KernelError("tree entry must link a blob id")
        names.append(_check_name(entry.get("name")).encode("utf-8"))
    if names != sorted(set(names)):
        raise KernelError("tree entries must be sorted and unique")
    for row in omitted:
        if not isinstance(row, dict) or set(row) != {"name", "reason"}:
            raise KernelError("malformed omitted tree entry")
        if not isinstance(row["reason"], str):
            raise KernelError("malformed omitted tree entry")
        if _check_name(row["name"]).encode("utf-8") in names:
            raise KernelError("a tree name is both an entry and omitted")
    return {"entries": entries, "omitted": omitted}


def put_tree(repo: Any, entries: list[dict[str, Any]], omitted: list[dict[str, str]] = ()) -> str:
    return repo.put("blob", encode_tree(entries, omitted), TREE_SCHEMA, redact=False)


def read_tree(repo: Any, oid: str) -> dict[str, Any]:
    envelope = repo.get(oid)
    if envelope.object_type != "blob" or envelope.schema != TREE_SCHEMA:
        raise KernelError(f"{oid} is not a tree")
    return parse_tree(envelope.body)


def is_tree(repo: Any, oid: str) -> bool:
    try:
        read_tree(repo, oid)
    except (KernelError, KeyError, ValueError, OSError):
        return False
    return True


Leaf = tuple[str, str, str, bool]


def walk(repo: Any, oid: str, prefix: str = "", depth: int = 0) -> Iterator[Leaf]:
    """Yield ``(path, mode, oid, redacted)`` per entry, ``(path, "omitted", reason, False)``."""
    if depth > MAX_DEPTH:
        raise KernelError("tree nesting exceeds its depth limit")
    tree = read_tree(repo, oid)
    for row in tree["omitted"]:
        yield prefix + row["name"], "omitted", row["reason"], False
    for entry in tree["entries"]:
        path = prefix + entry["name"]
        if entry["mode"] == DIR:
            yield path, DIR, entry["oid"], False
            yield from walk(repo, entry["oid"], path + "/", depth + 1)
        else:
            yield path, entry["mode"], entry["oid"], bool(entry.get("redacted"))


def link_tree(payload: dict[str, Any], tree_oid: str) -> dict[str, Any]:
    """Return a copy of an event *payload* linking *tree_oid* in its ``tree`` field."""
    if parse_oid(tree_oid)[0] != "blob":
        raise KernelError("a tree link must be a blob id")
    return {**payload, "tree": tree_oid}


__all__ = [
    "DIR",
    "EXEC",
    "FILE",
    "LINK",
    "TREE_TYPE",
    "encode_tree",
    "is_tree",
    "link_tree",
    "parse_tree",
    "put_tree",
    "read_tree",
    "walk",
]
