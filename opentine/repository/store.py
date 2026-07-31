"""Filesystem-backed v3 object database, refs, and reflogs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine._v3_guards import guarded_redaction
from opentine.kernel import KernelError, ObjectEnvelope, canonical_json, parse_oid, validate_links
from opentine.redaction import redact_blob
from opentine.repository._annotations import validate_annotation_chain
from opentine.repository._config import validate_config
from opentine.repository._objects import iter_object_oids, store_envelope
from opentine.repository._paths import atomic_bytes as _atomic_bytes
from opentine.repository._paths import ensure_layout, internal_files, internal_path, linklike
from opentine.repository._ref_store import commit_ref, read_ref_oid
from opentine.repository._refs import normalize_ref, validate_ref_oid, validate_ref_target
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
        ensure_layout(tine)
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
        for base in (candidate, *candidate.parents):
            tine = base if base.name == ".tine" else base / ".tine"
            if (tine / "config.json").exists():
                # Recreate any structural directory a version-control checkout
                # dropped while empty, so a committed repository opens intact.
                # Best-effort: read-only media cannot be healed, but the objects
                # and refs are still readable there, so opening must not fail.
                try:
                    ensure_layout(tine)
                except OSError:
                    pass
                return cls(tine)
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
            stored_payload = guarded_redaction(payload, where=f"v3 {object_type!r}", redact=redact)
        envelope = ObjectEnvelope.create(object_type, stored_payload, schema)
        validate_links(envelope, self._link_exists)
        validate_annotation_chain(self, envelope)
        validate_event_metrics(envelope)
        validate_run_graph(self, envelope)
        return self._store_envelope(envelope)

    def _store_envelope(self, envelope: ObjectEnvelope) -> str:
        return store_envelope(self, envelope)

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

    def raw_size(self, oid: str) -> int:
        from opentine.repository._blob_io import stored_object_size

        return stored_object_size(self, oid)

    def iter_oids(self, *, limit: int | None = None, truncate: bool = False) -> list[str]:
        return iter_object_oids(self.path, limit=limit, truncate=truncate)

    _ref_name = staticmethod(normalize_ref)

    def _read_ref_oid(self, name: str) -> str | None:
        return read_ref_oid(self.path, self._ref_name(name))

    def read_ref(self, name: str) -> str | None:
        normalized = self._ref_name(name)
        value = read_ref_oid(self.path, normalized)
        if value is None:
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
        validate_ref_oid(normalized, new_oid)
        target = self.get(new_oid)
        self._update_ref_validated(
            normalized,
            new_oid,
            target,
            expected_old=expected_old,
            actor=actor,
        )

    def _update_ref_validated(
        self,
        name: str,
        new_oid: str,
        target: ObjectEnvelope,
        expected_old: str | None | object = _UNSET,
        *,
        actor: str = "local",
    ) -> None:
        normalized = self._ref_name(name)
        validate_ref_oid(normalized, new_oid)
        if target.oid != new_oid:
            raise KernelError("validated ref target does not match its object id")
        validate_ref_target(normalized, target.object_type, target.payload())
        commit_ref(
            self.path,
            normalized,
            new_oid,
            None if expected_old is _UNSET else expected_old,
            expected_old is not _UNSET,
            actor,
        )

    def list_refs(self) -> dict[str, str]:
        refs: dict[str, str] = {}
        root = internal_path(self.path, "refs")
        for path in sorted(internal_files(self.path, "refs")):
            if path.name.casefold().endswith(".lock"):
                continue
            try:  # a name that is not a legal ref is not a ref: one stray .DS_Store
                name = self._ref_name(path.relative_to(root).as_posix())
            except ValueError:  # used to raise here, so fsck saw a healthy repo as
                continue  # broken with zero refs, masking every real error behind it
            if (value := read_ref_oid(self.path, name)) is not None:
                refs[name] = value
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
