"""Filesystem-backed v3 object database, refs, and reflogs."""

from __future__ import annotations

import os
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
from opentine.redaction import redact_blob, redact_value
from opentine.repository._annotations import validate_annotation_chain
from opentine.repository._config import validate_config
from opentine.repository._objects import iter_object_oids
from opentine.repository._paths import atomic_bytes as _atomic_bytes
from opentine.repository._paths import internal_files, internal_path, linklike
from opentine.repository._reflog import append_reflog
from opentine.repository._refs import normalize_ref, validate_ref_target
from opentine.repository._run_graph import validate_event_metrics, validate_run_graph
from opentine.repository._shallow import read_shallow, shallow_fingerprint

_UNSET = object()


class Repo:
    def __init__(self, tine_dir: str | Path):
        source = Path(tine_dir).expanduser()
        if linklike(source):
            raise KernelError("repository root cannot be a symlink")
        self.path = source.resolve()
        validate_config(internal_path(self.path, "config.json"))
        self._shallow_cache = None

    @classmethod
    def init(cls, path: str | Path = ".", *, bare: bool = False) -> Repo:
        root = Path(path).expanduser().resolve()
        tine = root if bare or root.name == ".tine" else root / ".tine"
        tine.mkdir(parents=True, exist_ok=True)
        for directory in (
            "objects",
            "refs/annotations",
            "refs/heads",
            "refs/tags",
            "logs",
            "packs",
            "indexes",
        ):
            internal_path(tine, *Path(directory).parts).mkdir(parents=True, exist_ok=True)
        config = internal_path(tine, "config.json")
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
        source = Path(path).expanduser()
        if source.name == ".tine" and linklike(source):
            raise KernelError("repository root cannot be a symlink")
        candidate = source.resolve()
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
        return internal_path(self.path, "objects", object_type, digest[:2], digest[2:])

    def has(self, oid: str) -> bool:
        try:
            return self._object_path(oid).is_file()
        except KernelError:
            return False

    def _shallow_set(self) -> frozenset[str]:
        path = internal_path(self.path, "shallow")
        fingerprint = shallow_fingerprint(path)
        if self._shallow_cache is None or self._shallow_cache[0] != fingerprint:
            self._shallow_cache = read_shallow(path)
        return self._shallow_cache[1]

    def _invalidate_shallow(self) -> None:
        self._shallow_cache = None

    def shallow_oids(self) -> set[str]:
        return set(self._shallow_set())

    def _link_exists(self, oid: str) -> bool:
        return self.has(oid) or oid in self._shallow_set()

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
            stored_payload = redact_value(_redact(payload)) if redact else payload
        envelope = ObjectEnvelope.create(object_type, stored_payload, schema)
        validate_links(envelope, self._link_exists)
        validate_annotation_chain(self, envelope)
        validate_event_metrics(envelope)
        validate_run_graph(self, envelope)
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
        validate_annotation_chain(self, envelope)
        validate_event_metrics(envelope)
        validate_run_graph(self, envelope)
        return envelope

    def raw(self, oid: str) -> bytes:
        try:
            return self._object_path(oid).read_bytes()
        except FileNotFoundError as exc:
            raise KeyError(oid) from exc

    def iter_oids(self, *, limit: int | None = None, truncate: bool = False) -> list[str]:
        return iter_object_oids(self.path, limit=limit, truncate=truncate)

    _ref_name = staticmethod(normalize_ref)

    def read_ref(self, name: str) -> str | None:
        normalized = self._ref_name(name)
        path = internal_path(self.path, "refs", *Path(normalized).parts)
        try:
            value = path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            return None
        try:
            target = self.get(value)
        except (KernelError, KeyError, OSError) as exc:
            raise ValueError(f"repository object is unavailable: {value}") from exc
        validate_ref_target(normalized, target.object_type, target.payload())
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
        target = self.get(new_oid)
        validate_ref_target(normalized, target.object_type, target.payload())
        ref_path = internal_path(self.path, "refs", *Path(normalized).parts)
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
        root = internal_path(self.path, "refs")
        for path in sorted(internal_files(self.path, "refs")):
            if path.suffix != ".lock":
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
        from opentine.repository.pack import MAX_PACK_OBJECTS, create_pack

        selected = self.iter_oids(limit=MAX_PACK_OBJECTS) if oids is None else oids
        return create_pack(self, selected)
