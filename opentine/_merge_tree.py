"""Three-way merge of flattened workspace trees (0.47, SPEC 4.19).

A *flat* tree maps a ``/``-joined path to its leaf ``{"mode", "oid"}`` (plus
``"redacted": true`` where set); directories are implied by the paths. Per
path, with ``b``, ``o``, ``t`` the base, ours and theirs leaves (``None`` when
absent): ``o == t`` takes ``o``; ``o == b`` takes ``t``; ``t == b`` takes
``o``; anything else is a **conflict**, recorded as ``{"kind": "tree", "path",
"base", "ours", "theirs"}`` (the blob oids, ``None`` when absent), and the
merged tree keeps ours. :func:`encode_trees` writes a flat tree back as the
nested schema-2 tree blobs of :mod:`opentine._tree`.
"""

from __future__ import annotations

from typing import Any

from opentine._tree import DIR, MODES, TREE_TYPE
from opentine.kernel import TREE_SCHEMA, KernelError, canonical_json, object_id, parse_oid

Flat = dict[str, dict[str, Any]]


def _leaf(value: Any, path: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) - {"mode", "oid", "redacted"}
        or value.get("mode") not in MODES - {DIR}
        or value.get("redacted", True) is not True
    ):
        raise KernelError(f"malformed tree leaf: {path}")
    parse_oid(value.get("oid"))
    parts = path.split("/")
    if not path or any(p in ("", ".", "..") or "\\" in p or "\0" in p for p in parts):
        raise KernelError(f"invalid tree path: {path!r}")
    return value


def check_flat(flat: Any) -> Flat:
    if not isinstance(flat, dict):
        raise KernelError("a flat tree is an object of path -> leaf")
    return {path: _leaf(leaf, path) for path, leaf in flat.items()}


def _oid(leaf: dict[str, Any] | None) -> str | None:
    return leaf["oid"] if leaf else None


def merge_flat(base: Flat | None, ours: Flat, theirs: Flat) -> tuple[Flat, list[dict[str, Any]]]:
    """The merged flat tree and its conflicts (sorted by path's UTF-8 bytes)."""
    base, ours, theirs = check_flat(base or {}), check_flat(ours), check_flat(theirs)
    merged: Flat = {}
    conflicts: list[dict[str, Any]] = []
    for path in sorted({*base, *ours, *theirs}, key=lambda p: p.encode("utf-8")):
        b, o, t = base.get(path), ours.get(path), theirs.get(path)
        if o == t or t == b:
            take = o
        elif o == b:
            take = t
        else:
            take = o
            conflicts.append({"kind": "tree", "path": path, "base": _oid(b), "ours": _oid(o),
                              "theirs": _oid(t)})  # fmt: skip
        if take is not None:
            merged[path] = take
    names = set(merged)
    for path in merged:  # a file where the other side has a directory
        prefix = path + "/"
        if any(other.startswith(prefix) for other in names):
            raise KernelError(f"tree merge puts a file and a directory at {path}")
    return merged, conflicts


def encode_trees(flat: Flat) -> tuple[str, dict[str, bytes]]:
    """``(root tree oid, {oid: body})`` for *flat*, every subtree included."""
    written: dict[str, bytes] = {}

    def build(rows: dict[str, dict[str, Any]]) -> str:
        files: list[dict[str, Any]] = []
        dirs: dict[str, dict[str, dict[str, Any]]] = {}
        for path, leaf in rows.items():
            head, _, rest = path.partition("/")
            if rest:
                dirs.setdefault(head, {})[rest] = leaf
            else:
                files.append({**leaf, "name": head})
        for name, sub in dirs.items():
            files.append({"mode": DIR, "name": name, "oid": build(sub)})
        files.sort(key=lambda row: row["name"].encode("utf-8"))
        body = canonical_json({"entries": files, "type": TREE_TYPE})
        oid = object_id("blob", TREE_SCHEMA, body)
        written[oid] = body
        return oid

    return build(flat), written


def flatten(repo: Any, oid: str | None) -> Flat | None:
    """A stored tree as a flat tree (directories and omitted names dropped)."""
    from opentine._tree import walk

    if not oid:
        return None
    out: Flat = {}
    for path, mode, leaf, redacted in walk(repo, oid):
        if mode in MODES - {DIR}:
            out[path] = {"mode": mode, "oid": leaf, **({"redacted": True} if redacted else {})}
    return out


__all__ = ["Flat", "check_flat", "encode_trees", "flatten", "merge_flat"]
