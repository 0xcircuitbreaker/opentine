"""Where ``tine prune --delete`` puts its victims before deleting them (X4, 0.35).

Deleting straight from the store raced a writer linking the same object: prune
checked the age, a writer re-touched or linked the object, then prune removed
it, leaving a ref to a broken run. Now each victim is first *moved* here (a
rename for a loose file; for a packed object, its canonical bytes are copied
here and its old pack renamed here). Only then are ages and reachability
checked again, and every victim that is young, sits in a re-touched pack, or is
reachable from a root (a ref or hold written meanwhile, or a young victim) is
restored. A writer's touch either lands before the move, so the check sees it,
or finds nothing and refuses the link (``_link_touch``). A quarantine left by a
crashed prune is restored in full by the next one.
"""

from __future__ import annotations

import os
import secrets
import shutil
from pathlib import Path

from opentine import _codec
from opentine.kernel import parse_oid
from opentine.repository._gc_tidy import remove_empty_dir
from opentine.repository._packs import MAX_OBJECT_BYTES
from opentine.repository._paths import atomic_bytes, durable_directory, internal_path
from opentine.repository._prune_roots import reachable
from opentine.repository._storage import write_object

QUARANTINE = "prune-quarantine"


def _name(oid: str) -> str:
    object_type, digest = parse_oid(oid)
    return f"{object_type}-{digest}"


def _oid(name: str) -> str:
    object_type, _, digest = name.partition("-")
    oid = f"{object_type}:sha256:{digest}"
    parse_oid(oid)
    return oid


class Quarantine:
    def __init__(self, repo, directory: Path | None = None):
        self.repo = repo
        base = internal_path(repo.path, QUARANTINE)
        self.dir = directory or base / secrets.token_hex(8)
        for part in ("loose", "raw", "packs"):
            durable_directory(self.dir / part)

    def __contains__(self, oid: str) -> bool:
        return any((self.dir / part / _name(oid)).exists() for part in ("loose", "raw"))

    def oids(self) -> set[str]:
        return {_oid(path.name) for part in ("loose", "raw") for path in self._files(part)}

    def _files(self, part: str) -> list[Path]:
        try:
            return sorted((self.dir / part).iterdir())
        except FileNotFoundError:
            return []

    def move_loose(self, oid: str) -> None:
        path = self.repo._object_path(oid)
        try:
            os.rename(path, self.dir / "loose" / _name(oid))
        except FileNotFoundError:
            return
        remove_empty_dir(path.parent)

    def stash(self, oid: str, raw: bytes) -> None:
        atomic_bytes(self.dir / "raw" / _name(oid), raw)

    def park_pack(self, path: Path) -> float:
        """Move a pack body here; return its mtime as it was when it moved."""
        parked = self.dir / "packs" / path.name
        os.rename(path, parked)
        return os.stat(parked).st_mtime

    def read(self, oid: str) -> bytes:
        try:
            return (self.dir / "raw" / _name(oid)).read_bytes()
        except FileNotFoundError:
            pass
        try:
            stored = (self.dir / "loose" / _name(oid)).read_bytes()
        except FileNotFoundError:
            raise KeyError(oid) from None
        return _codec.unwrap(stored, limit=MAX_OBJECT_BYTES)

    def young(self, cutoff: float) -> set[str]:
        return {_oid(p.name) for p in self._files("loose") if os.lstat(p).st_mtime > cutoff}

    def keep(self, roots: set[str]) -> set[str]:
        """The quarantined objects reachable from *roots* (through the store or here)."""
        return reachable(_View(self.repo, self), roots) & self.oids()

    def restore(self, oid: str) -> None:
        loose = self.dir / "loose" / _name(oid)
        if loose.exists():
            target = self.repo._object_path(oid)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(loose, target)  # never replaces a copy a writer just stored
            except FileExistsError:
                pass
            loose.unlink()
        raw = self.dir / "raw" / _name(oid)
        if raw.exists():
            write_object(self.repo, oid, raw.read_bytes())
            raw.unlink()

    def finish(self, keep: set[str]) -> int:
        """Restore *keep*, delete the rest; return how many objects were deleted."""
        for oid in sorted(keep):
            self.restore(oid)
        deleted = len(self.oids())
        shutil.rmtree(self.dir)
        return deleted

    def restore_all(self) -> None:
        self.finish(self.oids())


def recover(repo) -> int:
    """Restore everything a crashed prune left in quarantine; return the count."""
    base = internal_path(repo.path, QUARANTINE)
    count = 0
    for directory in sorted(base.iterdir()) if base.is_dir() else []:
        if directory.is_dir() and not directory.is_symlink():
            quarantine = Quarantine(repo, directory)
            count += len(quarantine.oids())
            quarantine.restore_all()
    return count


class _View:
    """``repo.raw``/``repo.has`` that also see quarantined objects."""

    def __init__(self, repo, quarantine: Quarantine):
        self.repo, self.quarantine = repo, quarantine

    def raw(self, oid: str) -> bytes:
        try:
            return self.repo.raw(oid)
        except KeyError:
            return self.quarantine.read(oid)

    def has(self, oid: str) -> bool:
        return self.repo.has(oid) or oid in self.quarantine
