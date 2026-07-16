"""Filesystem-backed v3 object database, refs, and reflogs."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from opentine._canon import _fsync_dir, _redact
from opentine.kernel import (
    KernelError,
    ObjectEnvelope,
    canonical_json,
    parse_oid,
    validate_links,
    verify_object,
)
from opentine.redaction import redact_blob
from opentine.repository._config import validate_config
from opentine.repository._reflog import append_reflog
from opentine.repository._refs import normalize_ref, validate_ref_target

_UNSET = object()


def _atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_dir(path.parent)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _repo_path(path: str | Path) -> Path:
    candidate = Path(path).expanduser().resolve()
    return candidate if candidate.name == ".tine" else candidate / ".tine"


class Repo:
    def __init__(self, tine_dir: str | Path):
        self.path = Path(tine_dir).resolve()
        validate_config(self.path / "config.json")

    @classmethod
    def init(cls, path: str | Path = ".", *, bare: bool = False) -> Repo:
        root = Path(path).expanduser().resolve()
        tine = root if bare or root.name == ".tine" else root / ".tine"
        for directory in ("objects", "refs/heads", "refs/tags", "logs", "packs", "indexes"):
            (tine / directory).mkdir(parents=True, exist_ok=True)
        config = tine / "config.json"
        if not config.exists():
            _atomic_bytes(
                config,
                canonical_json(
                    {
                        "format": 3,
                        "object_hash": "sha256",
                        "repository": "opentine",
                        "version": 1,
                    }
                )
                + b"\n",
            )
        return cls(tine)

    @classmethod
    def open(cls, path: str | Path = ".") -> Repo:
        candidate = Path(path).expanduser().resolve()
        if candidate.is_file():
            candidate = candidate.parent
        if candidate.name == ".tine" and (candidate / "config.json").exists():
            return cls(candidate)
        for parent in (candidate, *candidate.parents):
            if (parent / ".tine" / "config.json").exists():
                return cls(parent / ".tine")
        raise FileNotFoundError(f"no .tine repository from {path}")

    @property
    def worktree(self) -> Path:
        return self.path.parent

    def _object_path(self, oid: str) -> Path:
        object_type, digest = parse_oid(oid)
        return self.path / "objects" / object_type / digest[:2] / digest[2:]

    def has(self, oid: str) -> bool:
        try:
            return self._object_path(oid).is_file()
        except KernelError:
            return False

    def shallow_oids(self) -> set[str]:
        path = self.path / "shallow"
        return set(path.read_text(encoding="ascii").splitlines()) if path.exists() else set()

    def _link_exists(self, oid: str) -> bool:
        return self.has(oid) or oid in self.shallow_oids()

    def put(
        self,
        object_type: str,
        payload: Any,
        schema: int = 1,
        *,
        redact: bool = True,
    ) -> str:
        if redact and object_type == "blob":
            stored_payload = redact_blob(payload)
        else:
            stored_payload = _redact(payload) if redact else payload
        envelope = ObjectEnvelope.create(object_type, stored_payload, schema)
        validate_links(envelope, self._link_exists)
        path = self._object_path(envelope.oid)
        if not path.exists():
            _atomic_bytes(path, envelope.encode())
        else:
            verify_object(path.read_bytes(), envelope.oid, self._link_exists)
        return envelope.oid

    def get(self, oid: str) -> ObjectEnvelope:
        path = self._object_path(oid)
        try:
            stored = path.read_bytes()
        except FileNotFoundError as exc:
            raise KeyError(oid) from exc
        envelope = ObjectEnvelope.decode(stored, oid)
        validate_links(envelope, self._link_exists)
        return envelope

    def raw(self, oid: str) -> bytes:
        try:
            return self._object_path(oid).read_bytes()
        except FileNotFoundError as exc:
            raise KeyError(oid) from exc

    def iter_oids(self) -> list[str]:
        found: list[str] = []
        objects = self.path / "objects"
        for object_type in sorted(objects.iterdir() if objects.exists() else []):
            if not object_type.is_dir():
                continue
            for prefix in sorted(object_type.iterdir()):
                if not prefix.is_dir():
                    continue
                for item in sorted(prefix.iterdir()):
                    digest = prefix.name + item.name
                    if len(digest) == 64:
                        found.append(f"{object_type.name}:sha256:{digest}")
        return found

    _ref_name = staticmethod(normalize_ref)

    def read_ref(self, name: str) -> str | None:
        normalized = self._ref_name(name)
        path = self.path / "refs" / normalized
        try:
            value = path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            return None
        validate_ref_target(normalized, parse_oid(value)[0])
        return value

    def update_ref(
        self,
        name: str,
        new_oid: str,
        expected_old: str | None | object = _UNSET,
        *,
        actor: str = "local",
    ) -> None:
        normalized = self._ref_name(name)
        validate_ref_target(normalized, parse_oid(new_oid)[0])
        if not self.has(new_oid):
            raise KeyError(f"new ref target is missing: {new_oid}")
        ref_path = self.path / "refs" / normalized
        ref_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = ref_path.with_name(ref_path.name + ".lock")
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError as exc:
            raise ValueError(f"ref {normalized!r} is locked by a concurrent write") from exc
        committed = False
        try:
            old = self.read_ref(normalized)
            if expected_old is not _UNSET and old != expected_old:
                raise ValueError(f"concurrent ref update: expected {expected_old!r}, found {old!r}")
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write((new_oid + "\n").encode())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(lock_path, ref_path)
            committed = True
        finally:
            if not committed:
                if fd >= 0:
                    os.close(fd)
                lock_path.unlink(missing_ok=True)
        _fsync_dir(ref_path.parent)
        append_reflog(self.path, normalized, old, new_oid, actor)

    def list_refs(self) -> dict[str, str]:
        refs: dict[str, str] = {}
        root = self.path / "refs"
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix != ".lock":
                name = path.relative_to(root).as_posix()
                refs[name] = path.read_text(encoding="ascii").strip()
        return refs

    def fsck(self, *, deep: bool = True):
        from opentine.repository.verify import fsck

        return fsck(self, deep=deep)

    verify = fsck

    def log(self, ref: str = "heads/main", *, limit: int | None = None):
        from opentine.repository.ops import log

        return log(self, ref, limit=limit)

    def diff(self, left: str, right: str):
        from opentine.repository.ops import semantic_diff

        return semantic_diff(self, left, right)

    def pack(self, oids: list[str] | None = None) -> bytes:
        from opentine.repository.pack import create_pack

        return create_pack(self, oids or self.iter_oids())
