"""``packed-refs``: every ref of a repository in one file, written by ``tine gc``.

One file per ref costs one open per ref on every listing and a 4 KiB disk block
each. Once a repository opts in (``tine gc --pack-refs``), gc folds loose refs
into ``.tine/packed-refs``::

    # opentine packed-refs 1
    <oid> <ref>          one line per ref, sorted by name, unique

Reads look at the loose file first and fall back to the packed value, so every
write path (``commit_ref``, ``update_refs`` and its journal, recovery) stays as
it was: a loose ref shadows its packed value. Only a delete must touch both, and
it does so under the ref's lock *and* :data:`LOCK` (packed value first, then the
loose file), the same order gc uses, so a concurrent gc can never write back a
value a delete removed.

Compatibility: opentine 0.36 and older never read this file, so a repository
whose loose refs were removed would show them missing (and prune would treat
their objects as unreachable). The opt-in therefore raises the descriptor's
``min_reader`` to :data:`MIN_READER` (0.26-0.36 refuse to open it; object format
4 is required, which older releases already refuse), and gc removes a loose ref
only in such a repository. ``tine gc --unpack-refs`` writes every ref loose
again and lowers ``min_reader`` back.
"""

from __future__ import annotations

import os
from pathlib import Path

from opentine.kernel import KernelError, parse_oid
from opentine.repository import _winretry
from opentine.repository._paths import atomic_bytes, internal_path
from opentine.repository._refs import normalize_ref

FILE = "packed-refs"
LOCK = "packed-refs.lock"
HEADER = b"# opentine packed-refs 1\n"
MIN_READER = "0.37.0"
MAX_PACKED_BYTES = 16 * 1024 * 1024  # prune scans it as a root file (_prune_roots)
_CACHE: dict[str, tuple[tuple, dict[str, str]]] = {}


def parse_packed(raw: bytes) -> dict[str, str]:
    if not raw.startswith(HEADER) or not raw.endswith(b"\n"):
        raise KernelError("packed-refs is malformed")
    refs: dict[str, str] = {}
    previous = ""
    for line in raw[len(HEADER) :].decode("ascii").split("\n")[:-1]:
        oid, _, name = line.partition(" ")
        try:
            parse_oid(oid)
            valid = normalize_ref(name) == name and name > previous
        except (KernelError, ValueError):
            valid = False
        if not valid:
            raise KernelError("packed-refs has a malformed, unsorted or duplicate line")
        refs[name] = oid
        previous = name
    return refs


def encode_packed(refs: dict[str, str]) -> bytes:
    return HEADER + b"".join(f"{refs[name]} {name}\n".encode("ascii") for name in sorted(refs))


def read_packed(base: Path) -> dict[str, str]:
    """The packed refs of *base* (``{}`` without the file); cached by file identity."""
    path = internal_path(base, FILE)
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return {}
    key = (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    cached = _CACHE.get(str(path))
    if cached is not None and cached[0] == key:
        return cached[1]
    try:
        raw = _winretry.read_bytes(path, MAX_PACKED_BYTES + 1)
    except FileNotFoundError:
        return {}  # unpacked meanwhile: its refs are loose again
    if len(raw) > MAX_PACKED_BYTES:
        raise KernelError("packed-refs exceeds its size limit")
    try:
        refs = parse_packed(raw)
    except UnicodeDecodeError as exc:
        raise KernelError("packed-refs is not ASCII") from exc
    _CACHE[str(path)] = (key, refs)
    return refs


def write_packed(base: Path, refs: dict[str, str]) -> None:
    """Replace the file (the caller holds :data:`LOCK`); no refs removes it."""
    path = internal_path(base, FILE)
    if refs:
        atomic_bytes(path, encode_packed(refs))
    else:
        _winretry.unlink(path)
    _CACHE.pop(str(path), None)


def packed_lock(base: Path) -> Path:
    """Take :data:`LOCK` (waiting briefly for a live holder); the path to release."""
    from opentine.repository._lockfile import acquire
    from opentine.repository._ref_retry import RefLockContended, retry_contended

    path = internal_path(base, LOCK)

    def attempt() -> Path:
        try:
            os.close(acquire(path, 0o600))
        except FileExistsError as exc:
            raise RefLockContended(f"packed-refs is locked by another writer ({path})") from exc
        return path

    return retry_contended(attempt)


def drop_packed(base: Path, name: str) -> None:
    """Remove *name* from packed-refs; the caller holds the ref's lock and :data:`LOCK`."""
    refs = dict(read_packed(base))
    if refs.pop(name, None) is not None:
        write_packed(base, refs)


def refs_packed(config: dict[str, object]) -> bool:
    """Whether this descriptor opted in (``"refs": "packed"``, see the module doc)."""
    return config.get("refs") == "packed"
