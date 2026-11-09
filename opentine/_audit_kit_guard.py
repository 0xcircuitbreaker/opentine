"""Hostile-input guards for ``tine audit-kit`` (0.49 review).

* :func:`unpack` extracts a kit zip refusing unsafe names, links, duplicate
  names and archives past :data:`MAX_FILES` / :data:`MAX_BYTES` (a zip bomb);
* :func:`tree_problems` refuses a kit directory holding a symbolic link or any
  other non-regular entry, which ``SHA256SUMS`` would otherwise hash through;
* :func:`safe_run_file` accepts only ``runs/NAME`` paths from ``kit.json``;
* :func:`safe_stem` turns a bundle-supplied run id into a file name;
* :func:`unredacted` names runs the redaction ruleset would still change: a
  kit is made to be handed out, so ``build`` refuses them unless told otherwise.
"""

from __future__ import annotations

import hashlib
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

MAX_FILES = 10_000
MAX_BYTES = 4 << 30
_RUN_FILE = re.compile(r"runs/[^/\\:\x00-\x1f]+")
_STEM = re.compile(r"[A-Za-z0-9._-]{1,80}")


def unpack(archive: Path, room: Path) -> Path:
    """Extract a kit zip into *room*; the kit root is its single top directory."""
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_BYTES:
            raise ValueError("kit zip is larger than a kit can be")
        tops, seen = set(), set()
        for info in infos:
            name = info.filename
            parts = PurePosixPath(name).parts
            raw = name.rstrip("/").split("/")
            bad = name.startswith(("/", "\\")) or ":" in name or "\\" in name
            if bad or not parts or {"", ".", ".."} & set(raw):
                raise ValueError(f"unsafe name in kit zip: {name!r}")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError(f"link in kit zip: {name!r}")
            if name.casefold() in seen:
                raise ValueError(f"duplicate name in kit zip: {name!r}")
            seen.add(name.casefold())
            tops.add(parts[0])
        if len(tops) != 1:
            raise ValueError("a kit zip holds exactly one top-level directory")
        zf.extractall(room)
    return room / tops.pop()


def tree_problems(kit: Path) -> list[str]:
    """Kit entries that are neither a regular file nor a directory."""
    out = []
    for path in kit.rglob("*"):
        mode = path.lstat().st_mode
        if path.is_symlink() or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            out.append(path.relative_to(kit).as_posix())
    return sorted(out)


def safe_run_file(name: object) -> bool:
    return isinstance(name, str) and bool(_RUN_FILE.fullmatch(name)) and name not in BAD_RUN_FILES


BAD_RUN_FILES = ("runs/.", "runs/..")


def safe_stem(run_id: object, oid: str) -> str:
    """A file stem for a bundle's run: its id when harmless, else its oid's hash."""
    if isinstance(run_id, str) and _STEM.fullmatch(run_id) and set(run_id) != {"."}:
        return run_id
    return "run-" + hashlib.sha256(oid.encode("utf-8")).hexdigest()[:16]


def unredacted(paths: list[Path]) -> list[str]:
    """Run files whose decoded body the redaction ruleset would still change."""
    from opentine import _codec
    from opentine._artifact_io import MAX_TINE_ARTIFACT_BYTES
    from opentine.redaction import redact_blob

    found = []
    for path in paths:
        body = _codec.unwrap(path.read_bytes(), limit=MAX_TINE_ARTIFACT_BYTES)
        if redact_blob(body) != body:
            found.append(path.name)
    return found


__all__ = ["safe_run_file", "safe_stem", "tree_problems", "unpack", "unredacted"]
