"""The per-run scaffold manifest (0.88): a digest of every scaffold file, path by path.

:func:`build` walks the scaffold globs of a harness (:mod:`opentine._scaffold_files`)
under *root* and returns an ``opentine.scaffold-manifest/1`` document::

    {"schema": "opentine.scaffold-manifest/1", "harness": NAME,
     "source": "default"|"pinned", "globs": [...],
     "files": [{"path", "kind", "sha256", "bytes", "target", "resolved", "via"}, ...],
     "tree_sha256": HEX}

Entries are sorted by path. ``kind`` is ``file`` (``sha256`` of the raw bytes),
``link`` (``target`` is the link text; ``sha256`` is the target's digest only when
it resolves to a regular file inside *root*, which is never left), ``special``
(a FIFO or device: never opened), ``external`` (an include outside *root*: named,
never read) or ``missing`` (an include that names no file). A symlinked directory
is a ``link`` entry and is not descended into. ``via`` names the instruction file
whose ``@path`` line imported the entry (depth at most :data:`MAX_DEPTH`).
``tree_sha256`` is SHA-256 over a domain tag and the canonical JSON of ``files``,
so editing one skill file changes one entry and the tree digest.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any

from opentine._scaffold_files import INSTRUCTIONS, ScaffoldError, globs

SCHEMA = "opentine.scaffold-manifest/1"
DOMAIN = b"opentine.scaffold-manifest.v1\0"
MAX_FILES = 4096
MAX_DEPTH = 5
MAX_INCLUDE_BYTES = 1 << 20
_FENCE = re.compile(r"^\s*(```|~~~)")
_CODE = re.compile(r"`[^`]*`")
_IMPORT = re.compile(r"(?:^|(?<=\s))@((?:~/|/|\.{1,2}/)?[A-Za-z0-9_.~/-]+)")
_SKIP = {".git"}


def _wild(part: str) -> bool:
    return any(c in part for c in "*?[")


def _entry(root: Path, rel: str, via: str | None = None) -> dict[str, Any] | None:
    """The entry for *rel*; a symlinked component is the entry itself (never crossed)."""
    walk = root
    parts = rel.split("/")
    for index, part in enumerate(parts):
        walk = walk / part
        try:
            info = walk.lstat()
        except (FileNotFoundError, NotADirectoryError):
            return None if via is None else _row(rel, "missing", via=via)
        if stat.S_ISLNK(info.st_mode):
            return _link(root, "/".join(parts[: index + 1]), walk, via)
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            return None if via is None else _row(rel, "missing", via=via)
    if stat.S_ISDIR(info.st_mode):
        return None
    if not stat.S_ISREG(info.st_mode):
        return _row(rel, "special", target=f"mode:{stat.S_IFMT(info.st_mode):o}", via=via)
    digest, size = _hash(walk)
    return _row(rel, "file", sha256=digest, size=size, via=via)


def _row(path: str, kind: str, *, sha256: str | None = None, size: int | None = None,
         target: str | None = None, resolved: str | None = None,
         via: str | None = None) -> dict[str, Any]:  # fmt: skip
    return {"path": path, "kind": kind, "sha256": sha256, "bytes": size, "target": target,
            "resolved": resolved, "via": via}  # fmt: skip


def _hash(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 16):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _link(root: Path, rel: str, full: Path, via: str | None) -> dict[str, Any]:
    target = os.readlink(full)
    row = _row(rel, "link", target=Path(target).as_posix(), via=via)
    try:
        real, base = full.resolve(), root.resolve()
        inside = real.relative_to(base).as_posix()
        if stat.S_ISREG(real.stat().st_mode):
            row["sha256"], row["bytes"] = _hash(real)
            row["resolved"] = inside
    except (OSError, RuntimeError, ValueError):  # outside, dangling or a loop
        pass
    return row


def _walk(root: Path, glob: str, out: dict[str, dict[str, Any]]) -> None:
    from opentine._integrity import matches

    parts = glob.split("/")
    fixed = []
    for part in parts:
        if _wild(part):
            break
        fixed.append(part)
    if len(fixed) == len(parts):
        row = _entry(root, glob)
        if row is not None:
            out.setdefault(row["path"], row)
        return
    if fixed:
        row = _entry(root, "/".join(fixed))
        if row is not None:  # the fixed prefix is a link or a file: it is the entry
            out.setdefault(row["path"], row)
            return
    top = root.joinpath(*fixed)
    if not top.is_dir() or top.is_symlink():
        return
    for here, dirs, names in os.walk(top):
        base = Path(here)
        for name in sorted(dirs):
            full = base / name
            if name in _SKIP or full.is_symlink():
                dirs.remove(name)
                rel = full.relative_to(root).as_posix()
                if full.is_symlink() and (matches(glob, rel) or matches(glob, rel + "/x")):
                    out.setdefault(rel, _link(root, rel, full, None))
        for name in sorted(names):
            rel = (base / name).relative_to(root).as_posix()
            if matches(glob, rel) and rel not in out:
                row = _entry(root, rel)
                if row is not None:
                    out[rel] = row
            if len(out) > MAX_FILES:
                raise ScaffoldError("scaffold.too-many-files", f"more than {MAX_FILES} files")


def imports(text: str) -> list[str]:
    """The ``@path`` imports of an instruction file, outside code fences and spans."""
    found, fenced = [], False
    for line in text.splitlines():
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        for match in _IMPORT.finditer(_CODE.sub(" ", line)):
            token = match.group(1).rstrip(".,;:)")
            if ("/" in token or "." in token.lstrip(".")) and token not in found:
                found.append(token)
    return found


def _includes(root: Path, out: dict[str, dict[str, Any]]) -> None:
    from opentine._integrity import normalize

    queue = [(p, 0) for p, r in sorted(out.items())
             if p.rsplit("/", 1)[-1] in INSTRUCTIONS and r["sha256"]]  # fmt: skip
    while queue:
        rel, depth = queue.pop(0)
        row = out[rel]
        source = root / (row["resolved"] or rel)
        try:
            with source.open("rb") as handle:
                text = handle.read(MAX_INCLUDE_BYTES).decode("utf-8", "replace")
        except OSError:
            continue
        for token in imports(text)[:64]:
            if token.startswith(("~", "/")):
                out.setdefault(token, _row(token, "external", via=rel))
                continue
            name = normalize(str(Path(rel).parent.as_posix() + "/" + token))
            if name.split("/")[0] == "..":
                out.setdefault(token, _row(token, "external", via=rel))
                continue
            if name in out:
                continue
            found = _entry(root, name, via=rel)
            if found is None:
                continue
            out[name] = found
            if len(out) > MAX_FILES:
                raise ScaffoldError("scaffold.too-many-files", f"more than {MAX_FILES} files")
            if found["sha256"] and depth + 1 < MAX_DEPTH:
                queue.append((name, depth + 1))


def tree_digest(files: list[dict[str, Any]]) -> str:
    from opentine.kernel import canonical_json

    return hashlib.sha256(DOMAIN + canonical_json(files)).hexdigest()


def build(harness: str, root: str | Path = ".") -> dict[str, Any]:
    """The scaffold manifest of *harness* under *root* (see the module docstring)."""
    base = Path(root).absolute()
    patterns, source = globs(harness, base)
    found: dict[str, dict[str, Any]] = {}
    for glob in patterns:
        _walk(base, glob, found)
    _includes(base, found)
    files = [found[p] for p in sorted(found)]
    return {"schema": SCHEMA, "harness": harness, "source": source, "globs": patterns,
            "files": files, "tree_sha256": tree_digest(files)}  # fmt: skip


_SAME = ("kind", "sha256", "target", "resolved")


def diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """``{added, removed, changed, same}``: path lists, and ``changed`` rows with both sides."""
    a = {r["path"]: r for r in before["files"]}
    b = {r["path"]: r for r in after["files"]}
    changed = [{"path": p, "before": {k: a[p][k] for k in _SAME},
                "after": {k: b[p][k] for k in _SAME}}
               for p in sorted(a.keys() & b.keys())
               if any(a[p][k] != b[p][k] for k in _SAME)]  # fmt: skip
    return {"added": sorted(b.keys() - a.keys()), "removed": sorted(a.keys() - b.keys()),
            "changed": changed, "same": before["tree_sha256"] == after["tree_sha256"]}  # fmt: skip


__all__ = ["DOMAIN", "MAX_DEPTH", "MAX_FILES", "SCHEMA", "build", "diff", "imports",
           "tree_digest"]  # fmt: skip
